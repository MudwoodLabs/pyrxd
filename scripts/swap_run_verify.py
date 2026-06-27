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
    independent re-fetch adapters (Esplora / ElectrumX / ETH RPC), the p-link/provenance check, and the
    lucky-pass MARGIN grade (a PASS whose asset-claim only just beat the maker CSV refund window is flagged
    MARGINAL).
  * NOT YET (clearly marked TODO): the full before/after balance ledger ("made-whole" P&L); the intent-side
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
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# pyrxd is importable from the repo (editable install / src layout).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pyrxd.btc_wallet.taproot import (
    btc_input_outpoints_from_raw,
    scrape_secret,
)
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.transaction.transaction import Transaction

# Secret substrings forbidden in any cross-host / journal file (mirrors eth_swap_two_host._assert_public_only).
_SECRET_FORBIDDEN_KEYS = ("preimage", "p_hex", "wif", "secret", "privkey", "mnemonic", "seed")


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
        counter_funding = eth_contract = eth_chain_id = None
        if d["counter_chain"] == "btc":
            if "counter_funding" not in d:
                raise ValueError("btc counter_chain requires 'counter_funding' (txid:vout)")
            counter_funding = Outpoint.parse(str(d["counter_funding"]))
        else:  # eth
            if "eth_contract" not in d or "eth_chain_id" not in d:
                raise ValueError("eth counter_chain requires 'eth_contract' (0x addr) and 'eth_chain_id'")
            eth_contract = str(d["eth_contract"]).lower()
            if not (eth_contract.startswith("0x") and len(eth_contract) == 42):
                raise ValueError("eth_contract must be a 0x-prefixed 20-byte address")
            eth_chain_id = int(d["eth_chain_id"])
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
            asset_locked_at_height=(
                int(d["asset_locked_at_height"]) if d.get("asset_locked_at_height") is not None else None
            ),
            min_margin_blocks=int(d.get("min_margin_blocks", 2)),
            party_endpoints=tuple(str(e) for e in d.get("party_endpoints", [])),
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


def assert_independent_endpoints(verifier_urls: list[str], party_endpoints: tuple[str, ...]) -> None:
    """The verifier's corroboration sources MUST be hosts neither party ran (else it's not independent)."""
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


def _output_spk(raw_tx: bytes, vout: int) -> bytes:
    """The locking script (scriptPubKey) of output `vout` of a NON-segwit (RXD) raw tx."""
    tx = Transaction.from_hex(raw_tx)
    if tx is None:
        raise ValueError("could not parse RXD transaction bytes")
    if not (0 <= vout < len(tx.outputs)):
        raise ValueError(f"vout {vout} out of range (tx has {len(tx.outputs)} outputs)")
    return tx.outputs[vout].locking_script.serialize()


def verify_asset_leg(
    m: RunManifest, covenant_funding_tx: bytes, covenant_spend_tx: bytes | None
) -> tuple[AssetLeg, list[str]]:
    """Re-derive the RXD asset-leg disposition from the funding + spending tx bytes.

    1. The funding output MUST pay the re-derived covenant SPK (the asset was locked to the legit covenant).
    2. The spend's output[0] decides who got the asset: taker_holder => taker claimed; maker_holder => refund.
    """
    notes: list[str] = []
    funded_spk, taker_holder, maker_holder = rxd_expected_scripts(m)
    observed_funding_spk = _output_spk(covenant_funding_tx, m.covenant_funding.vout)
    if observed_funding_spk != funded_spk:
        return AssetLeg.ANOMALOUS, [
            "covenant funding output SPK does NOT match the covenant re-derived from public terms — "
            "the asset was not locked to the agreed covenant (PARAMS_MISMATCH territory)"
        ]
    notes.append("covenant funding SPK == re-derived covenant (asset locked to the agreed covenant)")
    if covenant_spend_tx is None:
        return AssetLeg.PENDING, [*notes, "covenant outpoint still unspent"]
    spent_to = _output_spk(covenant_spend_tx, 0)
    if spent_to == taker_holder:
        # claim path: the covenant claim scriptSig reveals p; confirm it hashes to H.
        try:
            p = scrape_secret(covenant_spend_tx, bytes.fromhex(m.h_hex))
            if _sha256(p) == bytes.fromhex(m.h_hex):
                notes.append("asset claim reveals a 32-byte p with sha256(p)==H")
        except Exception:
            notes.append("WARNING: asset paid the taker holder but p was not scrapeable from the spend")
        return AssetLeg.TAKER_CLAIMED, notes
    if spent_to == maker_holder:
        return AssetLeg.MAKER_REFUNDED, [*notes, "covenant spent to the maker holder (CSV refund)"]
    return AssetLeg.ANOMALOUS, [*notes, "covenant spent to NEITHER the taker nor maker holder script"]


def verify_counter_leg_btc(
    m: RunManifest, counter_spend_tx: bytes | None
) -> tuple[CounterLeg, bytes | None, list[str]]:
    """Re-derive the BTC counter-leg disposition. The claim leaf reveals p (and pays the maker); the refund
    leaf is a CSV spend back to the taker. We distinguish by whether p is scrapeable, and we require the
    spend to actually consume OUR HTLC funding outpoint (provenance)."""
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
    try:
        p = scrape_secret(counter_spend_tx, bytes.fromhex(m.h_hex))
        if _sha256(p) == bytes.fromhex(m.h_hex):
            return CounterLeg.MAKER_CLAIMED, p, [*notes, "counter claim reveals p with sha256(p)==H -> maker claimed"]
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
    m: RunManifest, claim_tx: dict | None, claim_receipt: dict | None
) -> tuple[CounterLeg, bytes | None, list[str]]:
    """Re-derive the ETH counter-leg disposition from an independently-fetched tx + receipt.

    Mirrors swap_coordinator.assert_claim_provenance (R6): the spend must (a) have SUCCEEDED (status==1 —
    a reverted-but-mined claim leaks p but moved no ETH), and (b) emit a Claimed/Refunded event FROM OUR
    contract instance. A claim's p is recovered from calldata + our-contract log data (recover_secret) and
    must appear in an our-contract log blob (topics||data). p scraped from a DIFFERENT contract is rejected."""
    from pyrxd.eth_wallet.secret import recover_secret  # lazy: keep the btc path web3/eth-free

    notes: list[str] = []
    if claim_tx is None or claim_receipt is None:
        return CounterLeg.PENDING, None, ["counter (ETH HTLC) has no cited claim/refund tx (unspent)"]
    assert m.eth_contract is not None  # guaranteed by manifest validation for eth
    contract = m.eth_contract.lower()
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
                return (
                    CounterLeg.MAKER_CLAIMED,
                    p,
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
    asset_p: bytes | None,
    counter_p: bytes | None,
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
        # p-link: the SAME secret links the two claims (atomicity in action).
        if asset_p is not None and counter_p is not None and asset_p != counter_p:
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

    def __init__(self, esplora_url: str):
        from pyrxd.network.bitcoin import MempoolSpaceSource  # lazy: only needed for a live run

        self._src = MempoolSpaceSource(base_url=esplora_url)

    async def raw_tx(self, txid: str) -> bytes:
        return bytes(await self._src.get_raw_tx(txid, min_confirmations=1))

    async def spend_of(self, op: Outpoint) -> bytes | None:
        # NOTE (first-cut): the harness must cite the counter-spend txid; outpoint->spender scanning over
        # Esplora (/outspend) is a next-cut convenience. Returns None to signal "look up the cited txid".
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
            return bytes(await c.get_transaction(txid))

    async def confirm_height(self, txid: str) -> int | None:
        """The block height a tx confirmed at (tip - confirmations + 1), or None if unconfirmed/unknown."""
        async with self._client as c:
            verbose = await c.get_transaction_verbose(txid)
            confs = int(verbose.get("confirmations", 0) or 0)
            if confs <= 0:
                return None
            tip = int(await c.get_tip_height())
            return tip - confs + 1

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

    async def close(self) -> None:
        await self._rpc.close()


async def _fetch_for_live(m: RunManifest, cited: dict, btc_url: str, rxd_url: str, eth_url: str | None):
    """Fetch (covenant_funding_tx, covenant_spend_tx|None, counter_obj) from INDEPENDENT sources. `cited`
    carries the only journal-trusted data: the spend tx ids. counter_obj is raw bytes (btc) or (tx,receipt)
    (eth)."""
    rxd = _RxdFetcher(rxd_url)
    asset_claim_height = None
    try:
        cov_fund = await rxd.raw_tx(m.covenant_funding.txid)
        spend_txid = cited.get("covenant_spend_txid")
        cov_spend = await rxd.raw_tx(spend_txid) if spend_txid else None
        if spend_txid:  # for the lucky-pass margin grade
            asset_claim_height = await rxd.confirm_height(spend_txid)
    finally:
        await rxd.close()

    counter_obj = None
    spend_id = cited.get("counter_spend_txid")
    if m.counter_chain == "btc":
        btc = _BtcFetcher(btc_url)
        try:
            counter_obj = await btc.raw_tx(spend_id) if spend_id else None
        finally:
            await btc.close()
    else:  # eth
        if spend_id:
            eth = _EthFetcher(eth_url, m.eth_chain_id)  # type: ignore[arg-type]
            try:
                counter_obj = await eth.tx_and_receipt(spend_id)
            finally:
                await eth.close()
    return cov_fund, cov_spend, counter_obj, asset_claim_height


def run_verify(
    m: RunManifest,
    covenant_funding_tx: bytes,
    covenant_spend_tx: bytes | None,
    counter_obj,
    *,
    asset_claim_height: int | None = None,
) -> VerifyResult:
    """The pure verification core — given re-fetched data, produce the verdict. counter_obj is raw bytes
    (btc) or a (tx_dict, receipt_dict) tuple (eth) or None. Network-free; the offline self-check uses it.
    `asset_claim_height` (the RXD covenant-spend confirm height) drives the lucky-pass margin grade."""
    asset, asset_notes = verify_asset_leg(m, covenant_funding_tx, covenant_spend_tx)
    if m.counter_chain == "btc":
        counter, counter_p, counter_notes = verify_counter_leg_btc(m, counter_obj)
    else:
        tx, rcpt = counter_obj if counter_obj else (None, None)
        counter, counter_p, counter_notes = verify_counter_leg_eth(m, tx, rcpt)
    asset_p = None  # we don't return the scraped asset p (avoid handling a secret); H-match already checked
    res = atomicity_verdict(m, asset, counter, asset_p, counter_p)
    grade, slack, margin_note = margin_grade(m, asset, counter, asset_claim_height)
    res.checks = {
        "counter_chain": m.counter_chain,
        "asset_leg_notes": asset_notes,
        "counter_leg_notes": counter_notes,
        "honest_party": m.honest_party,
        "margin": {"grade": grade, "slack_blocks": slack, "note": margin_note},
    }
    if res.verdict is Verdict.PASS and grade == "MARGINAL":
        res.reasons.append(f"PASS but MARGINAL: {margin_note}")
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

    def _rxd_tx(out_spk: bytes, value: int = 1000) -> bytes:
        tx = _Tx()
        tx.add_input(TransactionInput(source_txid="00" * 32, source_output_index=0, unlocking_script=Script(b"")))
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

    e1, e1p, _ = verify_counter_leg_eth(m_eth, claim_tx, claim_rcpt)
    check("ETH claim -> MAKER_CLAIMED (p recovered)", e1 is CounterLeg.MAKER_CLAIMED and e1p == p_eth)
    e2, _, _ = verify_counter_leg_eth(m_eth, {"input": "0x962e097e"}, refund_rcpt)
    check("ETH refund -> TAKER_REFUNDED", e2 is CounterLeg.TAKER_REFUNDED)
    e3, _, _ = verify_counter_leg_eth(m_eth, claim_tx, reverted_rcpt)
    check("ETH reverted claim -> ANOMALOUS", e3 is CounterLeg.ANOMALOUS)
    e4, _, _ = verify_counter_leg_eth(m_eth, claim_tx, foreign_rcpt)
    check("ETH claim from a FOREIGN contract -> ANOMALOUS", e4 is CounterLeg.ANOMALOUS)
    e5, _, _ = verify_counter_leg_eth(m_eth, None, None)
    check("ETH no cited spend -> PENDING", e5 is CounterLeg.PENDING)

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
    cov_fund, cov_spend, counter_obj, asset_claim_height = await _fetch_for_live(
        m, cited, args.btc_esplora_url, args.rxd_electrumx_url, args.eth_rpc_url
    )
    res = run_verify(m, cov_fund, cov_spend, counter_obj, asset_claim_height=asset_claim_height)
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
