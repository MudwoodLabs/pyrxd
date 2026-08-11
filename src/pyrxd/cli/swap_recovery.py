"""Cold swap-recovery core — the human fallback when automation refuses to broadcast.

**STRICTLY READ-ONLY. Nothing in this module broadcasts, and nothing here may ever
learn how.** That property is what keeps the cold toolkit outside the external swap
audit gate, exactly as ``pyrxd swap status`` is today (see
:mod:`pyrxd.cli.swap_cmds`): the commands built on this module PRINT raw transaction
hex and the operator broadcasts it themselves, from their own node, at a fee they
chose deliberately.

Why it exists now
-----------------
Gap-closure A1 established that **Radiant has neither RBF nor CPFP** (see
:mod:`pyrxd.gravity.fee_policy`): a time-critical claim or refund that fails to get
mined cannot be bumped by any means and squats on its own inputs for up to 8 hours.
Automation therefore now *refuses* to broadcast an unaffordable spend and pages
instead. This module is what the paged operator reaches for — build the spend cold,
read every field, decide the fee, broadcast by hand.

The three capabilities
----------------------
* :func:`recover_preimage_from_btc_claim` / :func:`recover_preimage_from_eth_claim` —
  scrape the preimage ``p`` off the counter-chain and re-verify it.
* :func:`build_cold_claim` / :func:`build_cold_refund` — rebuild the covenant, build
  the spend, and report the fee floor / deadline-aware target / CSV maturity beside it.
* :func:`read_btc_counter_leg` / :func:`read_eth_counter_leg` — the counter-leg read
  that lets ``swap status --check-chain`` notice the maker's claim revealing ``p``.

PROVENANCE IS NOT OPTIONAL (the security core of this module)
------------------------------------------------------------
A scrape that grabs any 32-byte push that happens to hash to ``H`` is a real
vulnerability, not a convenience: two swaps can legitimately share a hashlock (a maker
re-using ``H`` across offers, or an attacker who copies ``H`` from a public order into
a *decoy* transaction of their own). Matching on ``sha256(p) == H`` alone would let
that foreign transaction drive OUR claim.

So every recovery path re-runs the provenance discipline proven in
:mod:`pyrxd.gravity.watch.claim_executor` before it scrapes anything:

1. **Re-derive the txid from the fetched bytes** (:func:`btc_txid_from_raw`) and match
   it against the txid the source *reported*. A source that serves the wrong
   transaction is caught by the hash, never trusted — which is what makes a
   single-source read safe here.
2. **Confirm the transaction spends OUR funding outpoint**
   (:func:`btc_input_outpoints_from_raw`, exact 36-byte wire prevout — never an
   offset). This is the cross-swap-replay defence, and it is why the funding outpoint
   is MANDATORY on every path, including the offline one.
3. **Only then scrape**, by content (``sha256(p) == H`` over every witness push /
   every 32-byte window), never by position — the C-PARSER lesson.
4. **Re-verify independently** that ``sha256(p) == H`` on the returned value, so a
   future scraper bug cannot hand back a non-matching secret.

``p`` IS NEVER READ FROM THE RECOVERY FILE. The harness recovery JSON carries
``preimage_p_hex``, but on a maker's host that copy may still be a **pre-reveal**
secret: trusting it would let an operator "recover" a preimage the counter-chain has
not published and hand it to a claim they are not yet entitled to make. Only the
chain-scraped value is legitimate, and a chain-scraped ``p`` is already public by
construction — which is exactly why printing it is safe while printing the file's copy
never is.

Read-only enforcement
---------------------
* No broadcaster, coordinator, or key-holding leg is imported by name here.
* The Radiant reads go through the ElectrumX client's ``get_utxos`` / ``get_history`` /
  ``get_tip_height`` only.
* The BTC reads are Esplora **GET**s (``/outspend``, ``/hex``).
* Ethereum has no read transport other than JSON-RPC over HTTP POST, so the write
  surface is closed the only way it can be: :data:`ETH_READ_ONLY_RPC_METHODS` is a hard
  allowlist and :func:`eth_rpc_read` refuses anything outside it — ``eth_sendRawTransaction``
  included — before the session is ever touched.

Keys: the fee input must be signed (the covenant enforces a single output, so a
separate fee input pays the miner), which means this module handles one private key. It
signs with it and nothing else — no WIF, and no value derived from the recovery file's
``preimage_p_hex``, is ever placed in a returned dataclass or an emitted payload.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pyrxd.btc_wallet.taproot import (
    BtcOutpoint,
    btc_input_outpoints_from_raw,
    btc_txid_from_raw,
    scrape_secret,
)
from pyrxd.eth_wallet.secret import recover_secret
from pyrxd.gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY, DeadlineFeePolicy
from pyrxd.gravity.htlc_covenant import (
    HtlcCovenant,
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import KeyMaterialError, ValidationError

__all__ = [
    "ETH_READ_ONLY_RPC_METHODS",
    "ColdSpend",
    "CounterLegStatus",
    "CovenantChainState",
    "PreimageNotRevealed",
    "PreimageRecovery",
    "ProvenanceRefused",
    "RecoveryExtras",
    "assert_covenant_matches",
    "build_cold_claim",
    "build_cold_refund",
    "covenant_pkhs",
    "electrumx_script_hash",
    "eth_rpc_read",
    "fee_scriptpubkey",
    "fetch_btc_claim_bytes",
    "fetch_eth_claim_artifacts",
    "not_checked",
    "parse_outpoint",
    "parse_recovery_extras",
    "read_btc_counter_leg",
    "read_counter_leg",
    "read_covenant_chain_state",
    "read_eth_counter_leg",
    "read_fee_utxos",
    "rebuild_covenant",
    "recover_preimage_from_btc_claim",
    "recover_preimage_from_eth_claim",
    "select_fee_utxo",
]


class ProvenanceRefused(ValidationError):
    """A candidate claim transaction failed a provenance check, so nothing was scraped.

    Distinct from :class:`PreimageNotRevealed` on purpose: this means "these bytes are
    not ours / not what the source claimed", which is an ADVERSARIAL or misconfigured
    input, whereas a missing preimage is the ordinary "not revealed yet" state.
    """


class PreimageNotRevealed(ValidationError):
    """The transaction is provably ours, but carries no value hashing to ``H``.

    The benign, expected case: a refund spend of our funding outpoint (the counterparty
    timed out rather than claiming), or a claim that has not happened yet.
    """


# --------------------------------------------------------------------------- recovery-file extras

# The harness recovery JSON predates this toolkit and did NOT persist everything the cold
# path needs. Verified against the writers before they were changed:
#
#   * scripts/dust_swap_run.py -- PRINTED the BTC HTLC funding outpoint
#     (`rec.btc_locator.funding_outpoint.txid`) but never wrote it into `keys_payload`.
#   * scripts/eth_swap_two_host.py -- the ONLY writer that persisted
#     `eth_contract_address`; eth_swap_run.py / eth_swap_grief_run.py did not.
#   * NO writer persisted the covenant's `amount` parameter, which the covenant SPK is
#     built from and which a rebuild therefore needs.
#
# The runners now record all three (`btc_funding_outpoint` / `eth_contract_address` /
# `rxd_covenant_amount`, via `_dust_swap_shared.merge_into_mode_600`), but every file
# written before that change lacks them, so nothing here may REQUIRE them.
#
# Each is accepted as a CLI flag, parsed from the file when a newer writer does persist
# it, and (for the covenant amount) derived from the funded on-chain carrier value where
# that derivation is self-checking. The rebuilt SPK must equal the persisted one, so a
# wrong supplied value fails loudly instead of producing a spend of the wrong covenant.


@dataclass(frozen=True)
class RecoveryExtras:
    """Optional locator fields a recovery file MAY carry. Never holds key material."""

    btc_funding_outpoint: str | None = None
    eth_contract_address: str | None = None
    eth_deploy_tx_hash: str | None = None
    asset_genesis_ref: str | None = None
    asset_ft_amount: int | None = None
    asset_reveal_value: int | None = None
    rxd_covenant_amount: int | None = None
    taker_rxd_pkh_hex: str | None = None
    maker_rxd_pkh_hex: str | None = None


def _opt_str(d: dict[str, Any], key: str) -> str | None:
    v = d.get(key)
    return v if isinstance(v, str) and v else None


def _opt_int(d: dict[str, Any], key: str) -> int | None:
    v = d.get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def parse_recovery_extras(path: Path) -> RecoveryExtras:
    """Parse the OPTIONAL locator fields out of a recovery JSON (never any secret).

    Tolerant by design: every field is optional and a missing one simply becomes
    ``None`` so the CLI can ask for it via a flag. It deliberately does NOT read
    ``preimage_p_hex`` — see the module docstring for why that copy is not legitimate.
    """
    d = json.loads(path.read_text())
    if not isinstance(d, dict):
        raise ValidationError("recovery file is not a JSON object")
    return RecoveryExtras(
        btc_funding_outpoint=_opt_str(d, "btc_funding_outpoint"),
        eth_contract_address=_opt_str(d, "eth_contract_address"),
        eth_deploy_tx_hash=_opt_str(d, "eth_deploy_tx_hash"),
        asset_genesis_ref=_opt_str(d, "asset_genesis_ref"),
        asset_ft_amount=_opt_int(d, "asset_ft_amount"),
        asset_reveal_value=_opt_int(d, "asset_reveal_value"),
        rxd_covenant_amount=_opt_int(d, "rxd_covenant_amount"),
        taker_rxd_pkh_hex=_opt_str(d, "taker_rxd_pkh"),
        maker_rxd_pkh_hex=_opt_str(d, "maker_rxd_pkh"),
    )


def _pkh_from_wif(wif: str) -> bytes:
    """Hash a WIF to its pkh, never letting the WIF into an error message.

    ``pyrxd.base58`` is the source-level fix for that (its decode failures carry a
    static message and no ``__cause__``); this is the matching call-site guard, so
    an unreadable ``*_rxd_wif`` in a hand-edited recovery file surfaces as a clean
    typed error rather than an "unexpected failure" at the CLI boundary. The
    exception is re-raised ``from None`` as a second, independent barrier — this
    function must not depend on any other module's message hygiene.
    """
    try:
        return bytes(PrivateKey(wif).public_key().hash160())
    except Exception:
        raise KeyMaterialError(
            "could not decode a WIF from the recovery file. The offending value is "
            "deliberately not shown — it is a private key. Check it for a line wrap, "
            "a stray space, or an O/I/l typo, or pass the public --taker-pkh/--maker-pkh instead."
        ) from None


def covenant_pkhs(
    path: Path, *, taker_pkh_hex: str | None = None, maker_pkh_hex: str | None = None
) -> tuple[bytes, bytes]:
    """Resolve ``(taker_pkh, maker_pkh)`` for a covenant rebuild — WIFs never leave here.

    Precedence: explicit ``--taker-pkh`` / ``--maker-pkh`` overrides, then a
    ``taker_rxd_pkh`` / ``maker_rxd_pkh`` field, then the ``*_rxd_wif`` fields a
    single-operator harness file carries (hashed to a pkh immediately; the WIF is not
    retained, returned, or logged).

    The two-host harnesses persist only the LOCAL role's key, which is why the explicit
    pkh flags exist: a maker recovering alone still needs the taker's pkh to rebuild the
    covenant, and a pkh is public.
    """
    d = json.loads(path.read_text())
    if not isinstance(d, dict):
        raise ValidationError("recovery file is not a JSON object")

    def _resolve(role: str, override: str | None) -> bytes:
        if override:
            raw = bytes.fromhex(override)
            if len(raw) != 20:
                raise ValidationError(f"--{role}-pkh must be 20 bytes (40 hex chars)")
            return raw
        field_pkh = _opt_str(d, f"{role}_rxd_pkh")
        if field_pkh:
            raw = bytes.fromhex(field_pkh)
            if len(raw) != 20:
                raise ValidationError(f"recovery file {role}_rxd_pkh must be 20 bytes")
            return raw
        wif = _opt_str(d, f"{role}_rxd_wif")
        if wif:
            return _pkh_from_wif(wif)
        raise ValidationError(
            f"cannot determine the {role} RXD pkh: the recovery file has neither "
            f"{role}_rxd_pkh nor {role}_rxd_wif. Pass --{role}-pkh <40-hex> "
            "(a pkh is public; the two-host harnesses persist only the local role's key)."
        )

    return _resolve("taker", taker_pkh_hex), _resolve("maker", maker_pkh_hex)


def parse_outpoint(value: str, *, what: str = "outpoint") -> BtcOutpoint:
    """Parse ``"<txid>:<vout>"`` into a :class:`BtcOutpoint` (fail-closed)."""
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValidationError(f"{what} must be 'txid:vout'")
    txid, vout_s = value.split(":")
    try:
        vout = int(vout_s)
    except ValueError:
        raise ValidationError(f"{what} vout must be an integer") from None
    return BtcOutpoint(txid=txid, vout=vout)


# --------------------------------------------------------------------------- preimage recovery


@dataclass(frozen=True)
class PreimageRecovery:
    """A provenance-checked, independently re-verified preimage.

    ``preimage_hex`` is safe to print: it was scraped from a transaction that is already
    on the counter-chain, so it is public the moment it exists. (The recovery FILE's
    ``preimage_p_hex`` is not, and is never a source here.)
    """

    preimage_hex: str
    hashlock_hex: str
    counter_chain: str  # "btc" | "eth"
    source: str  # where in the tx it was found
    claim_txid: str | None
    provenance: tuple[str, ...]  # the checks that PASSED, for the operator to read


def _verify_hashes_to(p: bytes, hashlock: bytes) -> None:
    """Independent re-verification, deliberately duplicating the scraper's own match.

    Cheap, and it means a scraper regression cannot hand back a value that does not
    open the lock — this is the last gate before ``p`` is printed and used to build a
    claim, so it fails closed rather than trusting the layer below.
    """
    if len(p) != 32 or hashlib.sha256(bytes(p)).digest() != bytes(hashlock):
        raise ProvenanceRefused("recovered value does not hash to the swap's hashlock H; refusing it")


def recover_preimage_from_btc_claim(
    raw_tx: bytes,
    *,
    hashlock: bytes,
    funding_outpoint: BtcOutpoint,
    reported_txid: str | None = None,
) -> PreimageRecovery:
    """Scrape ``p`` from a BTC claim transaction, PROVENANCE FIRST. Pure — no network.

    This is the offline core: the online path fetches the bytes and calls straight into
    here, and ``--claim-tx-hex`` hands operator-supplied bytes to the same function. The
    checks do not weaken for the offline case — ``funding_outpoint`` is required either
    way, because it is the only thing that distinguishes OUR swap's claim from a
    same-hashlock decoy.

    Raises
    ------
    ProvenanceRefused
        The bytes do not hash to ``reported_txid``, do not spend ``funding_outpoint``,
        or are structurally unparseable.
    PreimageNotRevealed
        The transaction is ours but reveals no ``p`` (typically a refund).
    """
    if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
        raise ValidationError("hashlock must be 32 bytes")
    raw = bytes(raw_tx)
    checks: list[str] = []

    # 1. SERIALIZE, don't trust: the txid must be that of THESE bytes.
    try:
        derived = btc_txid_from_raw(raw)
    except ValidationError as exc:
        raise ProvenanceRefused(f"claim transaction bytes are unparseable: {exc}") from exc
    if reported_txid is not None and derived != reported_txid:
        raise ProvenanceRefused(
            f"fetched bytes hash to {derived}, not the reported spender {reported_txid} — "
            "the source served a different transaction; refusing to scrape it"
        )
    checks.append(f"txid re-derived from the bytes = {derived}")

    # 2. Cross-swap-replay defence: it must spend OUR funding outpoint.
    try:
        prevouts = btc_input_outpoints_from_raw(raw)
    except ValidationError as exc:
        raise ProvenanceRefused(f"claim transaction inputs are unparseable: {exc}") from exc
    if funding_outpoint.prevout_bytes() not in prevouts:
        raise ProvenanceRefused(
            f"transaction {derived} does not spend this swap's funding outpoint "
            f"{funding_outpoint.txid}:{funding_outpoint.vout} — a transaction that merely shares "
            "the hashlock H is NOT this swap's claim; refusing to scrape it"
        )
    checks.append(f"spends our funding outpoint {funding_outpoint.txid}:{funding_outpoint.vout}")

    # 3. Scrape by content over every witness push of every input (never by offset).
    try:
        p = scrape_secret(raw, bytes(hashlock))
    except (ValidationError, ValueError) as exc:
        raise PreimageNotRevealed(
            f"transaction {derived} spends our funding outpoint but reveals no preimage "
            "(this is what a REFUND looks like — the counterparty timed out rather than claiming)"
        ) from exc

    # 4. Independent re-verification.
    _verify_hashes_to(p, bytes(hashlock))
    checks.append("sha256(p) == H re-verified independently of the scraper")
    return PreimageRecovery(
        preimage_hex=bytes(p).hex(),
        hashlock_hex=bytes(hashlock).hex(),
        counter_chain="btc",
        source="btc_claim_witness",
        claim_txid=derived,
        provenance=tuple(checks),
    )


def _hex_blob(value: object) -> bytes:
    """Decode a 0x-hex JSON-RPC field to bytes; unusable values become empty (skipped)."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        return b""
    s = value[2:] if value.startswith(("0x", "0X")) else value
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def _same_address(a: object, b: object) -> bool:
    """EIP-55-insensitive address comparison (RPCs disagree on checksum casing)."""
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()


def recover_preimage_from_eth_claim(
    *,
    hashlock: bytes,
    contract_address: str,
    claim_tx: dict[str, Any],
    logs: Sequence[dict[str, Any]] = (),
    reported_tx_hash: str | None = None,
) -> PreimageRecovery:
    """Scrape ``p`` from an ETH claim, PROVENANCE FIRST. Pure — no network.

    The ETH analogue of the BTC funding-outpoint bind is the **per-swap-unique HTLC
    contract address**: each swap deploys a fresh contract, so "bound to this address"
    is the same statement as "belongs to this swap". Only blobs bound to
    ``contract_address`` are scanned:

    * the transaction's calldata, when it calls the contract directly (``to == contract``), and
    * the ``data`` of each log emitted BY the contract IN this transaction.

    A transaction that neither calls our contract nor emitted a log from it is refused
    outright — that is the case a hashlock-sharing decoy falls into. Note that a scraped
    ``p`` proves only that ``p`` is PUBLIC, not that the claim succeeded: a reverted
    call is still mined and still exposes calldata. That distinction belongs to the
    coordinator's finality gate, not here; for the cold path a public ``p`` is exactly
    what the operator needs.
    """
    if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
        raise ValidationError("hashlock must be 32 bytes")
    if not isinstance(contract_address, str) or not contract_address:
        raise ValidationError("contract_address is required for ETH preimage provenance")
    if not isinstance(claim_tx, dict):
        raise ProvenanceRefused("claim transaction JSON is not an object")

    tx_hash = claim_tx.get("hash")
    tx_hash_s = tx_hash if isinstance(tx_hash, str) else None
    if reported_tx_hash is not None and not _same_address(tx_hash_s, reported_tx_hash):
        raise ProvenanceRefused(
            f"fetched transaction reports hash {tx_hash_s!r}, not the requested {reported_tx_hash!r} — "
            "the RPC served a different transaction; refusing to scrape it"
        )

    checks: list[str] = []
    blobs: list[bytes] = []
    source = "eth_claim_log_data"
    if _same_address(claim_tx.get("to"), contract_address):
        blobs.append(_hex_blob(claim_tx.get("input")))
        checks.append(f"transaction calls our per-swap HTLC contract {contract_address}")
        source = "eth_claim_calldata"

    bound_logs = [
        lg
        for lg in logs
        if isinstance(lg, dict)
        and _same_address(lg.get("address"), contract_address)
        and (tx_hash_s is None or _same_address(lg.get("transactionHash"), tx_hash_s))
    ]
    for lg in bound_logs:
        blobs.append(_hex_blob(lg.get("data")))
        for topic in lg.get("topics") or []:
            blobs.append(_hex_blob(topic))
    if bound_logs:
        checks.append(f"{len(bound_logs)} log(s) emitted by {contract_address} in this transaction")

    if not blobs:
        raise ProvenanceRefused(
            f"transaction {tx_hash_s or '<unknown>'} neither calls nor emitted a log from the swap's "
            f"HTLC contract {contract_address} — it is not this swap's claim; refusing to scrape it"
        )

    try:
        p = recover_secret(blobs, bytes(hashlock))
    except (ValidationError, ValueError) as exc:
        raise PreimageNotRevealed(
            f"transaction {tx_hash_s or '<unknown>'} is bound to our HTLC contract but reveals no "
            "preimage (a REFUND, or a call that did not carry p)"
        ) from exc
    _verify_hashes_to(p, bytes(hashlock))
    checks.append("sha256(p) == H re-verified independently of the scraper")
    return PreimageRecovery(
        preimage_hex=bytes(p).hex(),
        hashlock_hex=bytes(hashlock).hex(),
        counter_chain="eth",
        source=source,
        claim_txid=tx_hash_s,
        provenance=tuple(checks),
    )


# --------------------------------------------------------------------------- counter-leg reads

#: Every Ethereum JSON-RPC method this toolkit is permitted to call. Ethereum has no
#: read transport other than JSON-RPC over HTTP POST, so "never POST" is not expressible
#: here the way it is for the Esplora GETs; this allowlist is the equivalent guarantee,
#: and :func:`eth_rpc_read` checks it BEFORE the session is touched. Adding a write
#: method here (``eth_sendRawTransaction``, ``eth_sendTransaction``, ``personal_*``)
#: would put the cold toolkit inside the audit gate — do not.
ETH_READ_ONLY_RPC_METHODS = frozenset(
    {
        "eth_blockNumber",
        "eth_chainId",
        "eth_getLogs",
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
    }
)


@dataclass(frozen=True)
class CounterLegStatus:
    """What the counter-chain says about this swap. ``p`` itself is deliberately absent.

    ``preimage_available`` reports only that a preimage IS recoverable; extracting it is
    ``pyrxd swap recover-preimage``. Keeping the value out of ``status`` means the
    common, casual command never prints a secret-shaped string, and the command that
    does print one is the one the operator invoked on purpose.
    """

    chain: str  # "btc" | "eth"
    state: str  # NOT_CHECKED | LOCKED | CLAIMED_PREIMAGE_REVEALED | SPENT_NO_PREIMAGE | ERROR
    reason: str
    claim_txid: str | None = None
    preimage_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain,
            "state": self.state,
            "reason": self.reason,
            "claim_txid": self.claim_txid,
            "preimage_available": self.preimage_available,
        }


def not_checked(chain: str, reason: str) -> CounterLegStatus:
    """The counter-leg was not read, and WHY — reported, never raised.

    A missing endpoint is a configuration fact, not a failure: ``swap status`` must
    still print the RXD covenant verdict it did obtain. Failing the whole command
    because the optional half was unconfigured would be strictly worse for an operator
    who is mid-incident.
    """
    return CounterLegStatus(chain=chain, state="NOT_CHECKED", reason=reason)


async def fetch_btc_claim_bytes(
    session: Any, base_url: str, funding_outpoint: BtcOutpoint, *, timeout_s: float = 15.0
) -> tuple[bool, str | None, bytes | None]:
    """Esplora GET pair: ``(spent, spender_txid, raw_bytes)`` for a funding outpoint.

    Reuses the watchtower's proven keyless read helpers rather than re-implementing
    them. They are imported lazily: ``pyrxd.gravity.watch``'s package ``__init__``
    eagerly pulls the whole tower (reconciler, executors, the ETH RPC client) into
    ``sys.modules``, and the CLI must not pay that on every invocation just to own a
    command it may not run.
    """
    from pyrxd.gravity.watch.adapters import mempool_space_outspend, mempool_space_tx_hex

    spent, spender = await mempool_space_outspend(
        session, base_url, funding_outpoint.txid, funding_outpoint.vout, timeout_s=timeout_s
    )
    if not spent or not spender:
        return False, None, None
    raw = await mempool_space_tx_hex(session, base_url, spender, timeout_s=timeout_s)
    return True, spender, raw


async def read_btc_counter_leg(
    session: Any, base_url: str, *, funding_outpoint: BtcOutpoint, hashlock: bytes, timeout_s: float = 15.0
) -> CounterLegStatus:
    """Classify the BTC counter-leg through the SAME provenance-checked path as recovery."""
    spent, spender, raw = await fetch_btc_claim_bytes(session, base_url, funding_outpoint, timeout_s=timeout_s)
    if not spent:
        return CounterLegStatus(
            chain="btc",
            state="LOCKED",
            reason=(
                f"BTC funding outpoint {funding_outpoint.txid}:{funding_outpoint.vout} is UNSPENT — "
                "the counterparty has not claimed, so no preimage has been revealed."
            ),
        )
    if not raw:
        return CounterLegStatus(
            chain="btc",
            state="ERROR",
            reason=f"outpoint is spent by {spender} but its raw bytes are not retrievable yet (unindexed?)",
            claim_txid=spender,
        )
    try:
        rec = recover_preimage_from_btc_claim(
            raw, hashlock=hashlock, funding_outpoint=funding_outpoint, reported_txid=spender
        )
    except PreimageNotRevealed as exc:
        return CounterLegStatus(chain="btc", state="SPENT_NO_PREIMAGE", reason=str(exc), claim_txid=spender)
    except ProvenanceRefused as exc:
        return CounterLegStatus(chain="btc", state="ERROR", reason=str(exc), claim_txid=spender)
    return CounterLegStatus(
        chain="btc",
        state="CLAIMED_PREIMAGE_REVEALED",
        reason=(
            f"the counterparty CLAIMED in {rec.claim_txid} and the preimage p is now PUBLIC on BTC. "
            "Extract it with `pyrxd swap recover-preimage`, then `pyrxd swap build-claim` while the "
            "covenant's CSV refund window is still shut."
        ),
        claim_txid=rec.claim_txid,
        preimage_available=True,
    )


async def eth_rpc_read(session: Any, rpc_url: str, method: str, params: list[Any], *, timeout_s: float = 15.0) -> Any:
    """One read-only Ethereum JSON-RPC call. Refuses any method outside the allowlist.

    The allowlist check runs BEFORE the session is touched, so a write method cannot
    reach the network even transiently — the refusal is a local ``ValidationError``, not
    a rejected request.
    """
    if method not in ETH_READ_ONLY_RPC_METHODS:
        raise ValidationError(
            f"{method!r} is not one of this toolkit's read-only RPC methods "
            f"({', '.join(sorted(ETH_READ_ONLY_RPC_METHODS))}). The cold recovery toolkit never "
            "writes to a chain — it prints transaction hex for you to broadcast yourself."
        )
    from pyrxd.gravity.watch.adapters import aiohttp_timeout

    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    async with session.post(rpc_url, json=payload, timeout=aiohttp_timeout(timeout_s)) as resp:
        resp.raise_for_status()
        body = await resp.json()
    if not isinstance(body, dict):
        raise ValidationError(f"{method}: RPC returned a non-object response")
    if body.get("error"):
        raise ValidationError(f"{method}: RPC error {body['error']!r}")
    return body.get("result")


async def fetch_eth_claim_artifacts(
    session: Any,
    rpc_url: str,
    *,
    contract_address: str,
    from_block: int | str = "0x0",
    timeout_s: float = 15.0,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Read ``(claim_tx, logs)`` for a per-swap HTLC contract. Read-only RPC only.

    Scans every log from the contract (selector-agnostic, mirroring
    :class:`~pyrxd.gravity.watch.eth_adapters.RpcEthChainSource`) so a differently
    shaped claim event is never silently missed, then fetches the transaction that
    emitted the LAST one.
    """
    logs = await eth_rpc_read(
        session,
        rpc_url,
        "eth_getLogs",
        [{"address": contract_address, "fromBlock": from_block, "toBlock": "latest"}],
        timeout_s=timeout_s,
    )
    logs = [lg for lg in (logs or []) if isinstance(lg, dict)]
    if not logs:
        return None, []
    tx_hash = logs[-1].get("transactionHash")
    if not isinstance(tx_hash, str):
        return None, logs
    tx = await eth_rpc_read(session, rpc_url, "eth_getTransactionByHash", [tx_hash], timeout_s=timeout_s)
    return (tx if isinstance(tx, dict) else None), logs


async def read_eth_counter_leg(
    session: Any, rpc_url: str, *, contract_address: str, hashlock: bytes, timeout_s: float = 15.0
) -> CounterLegStatus:
    """Classify the ETH counter-leg through the SAME provenance-checked path as recovery."""
    tx, logs = await fetch_eth_claim_artifacts(session, rpc_url, contract_address=contract_address, timeout_s=timeout_s)
    if tx is None:
        return CounterLegStatus(
            chain="eth",
            state="LOCKED",
            reason=(
                f"the HTLC contract {contract_address} has emitted no retrievable claim activity — "
                "no preimage has been revealed."
            ),
        )
    tx_hash = tx.get("hash") if isinstance(tx.get("hash"), str) else None
    try:
        rec = recover_preimage_from_eth_claim(
            hashlock=hashlock, contract_address=contract_address, claim_tx=tx, logs=logs
        )
    except PreimageNotRevealed as exc:
        return CounterLegStatus(chain="eth", state="SPENT_NO_PREIMAGE", reason=str(exc), claim_txid=tx_hash)
    except ProvenanceRefused as exc:
        return CounterLegStatus(chain="eth", state="ERROR", reason=str(exc), claim_txid=tx_hash)
    return CounterLegStatus(
        chain="eth",
        state="CLAIMED_PREIMAGE_REVEALED",
        reason=(
            f"the counterparty CLAIMED in {rec.claim_txid} and the preimage p is now PUBLIC on ETH. "
            "Extract it with `pyrxd swap recover-preimage`, then `pyrxd swap build-claim` while the "
            "covenant's CSV refund window is still shut."
        ),
        claim_txid=rec.claim_txid,
        preimage_available=True,
    )


async def open_http_session() -> Any:
    """A fresh aiohttp session. Imported lazily so ``pyrxd --help`` does not pay for it."""
    import aiohttp

    return aiohttp.ClientSession()


async def read_counter_leg(
    facts: Any,
    extras: RecoveryExtras,
    *,
    btc_outpoint: str | None = None,
    btc_api_url: str | None = None,
    eth_contract: str | None = None,
    eth_rpc_url: str | None = None,
    timeout_s: float = 15.0,
) -> CounterLegStatus:
    """Read the swap's counter-leg for ``swap status --check-chain``.

    Lives here rather than beside the click command so ``swap_cmds`` can call it without
    importing the cold-spend command module (which imports ``swap_cmds`` in turn).

    Returns :func:`not_checked` with the reason when the endpoint or the locator is
    missing, rather than raising: the RXD covenant verdict is still worth printing, and
    an operator mid-incident should not lose it because the optional half of the read
    was unconfigured.
    """
    hashlock = bytes.fromhex(facts.hashlock_hex)
    if facts.counter_chain == "btc":
        outpoint = btc_outpoint or extras.btc_funding_outpoint
        if not outpoint:
            return not_checked(
                "btc",
                "no BTC funding outpoint in the recovery file — files written before the harnesses "
                "started persisting `btc_funding_outpoint` only printed it to the console. "
                "Pass --btc-funding-outpoint TXID:VOUT to check the counter-leg.",
            )
        if not btc_api_url:
            return not_checked("btc", "no --btc-api-url configured for the counter-leg read.")
        try:
            op = parse_outpoint(outpoint, what="--btc-funding-outpoint")
        except ValidationError as exc:
            return CounterLegStatus(chain="btc", state="ERROR", reason=str(exc))
        session = await open_http_session()
        async with session:
            return await read_btc_counter_leg(
                session, btc_api_url, funding_outpoint=op, hashlock=hashlock, timeout_s=timeout_s
            )

    contract = eth_contract or extras.eth_contract_address
    if not contract:
        return not_checked(
            "eth",
            "no ETH HTLC contract address in the recovery file — before the harness change only "
            "scripts/eth_swap_two_host.py persisted `eth_contract_address`. "
            "Pass --eth-contract 0x… to check the counter-leg.",
        )
    if not eth_rpc_url:
        return not_checked("eth", "no --eth-rpc-url configured for the counter-leg read.")
    session = await open_http_session()
    async with session:
        return await read_eth_counter_leg(
            session, eth_rpc_url, contract_address=contract, hashlock=hashlock, timeout_s=timeout_s
        )


# --------------------------------------------------------------------------- Radiant reads


def electrumx_script_hash(spk: bytes | str) -> str:
    """ElectrumX ``script_hash`` for a raw scriptPubKey: ``sha256(spk)`` reversed."""
    raw = bytes.fromhex(spk) if isinstance(spk, str) else bytes(spk)
    return hashlib.sha256(raw).digest()[::-1].hex()


@dataclass(frozen=True)
class CovenantChainState:
    """The funded covenant UTXO as read from ElectrumX. Read-only, no mempool writes.

    The three depth fields are ONE measurement written three ways, and
    ``__post_init__`` refuses any triple a chain could not produce:

    * unconfirmed ⇔ ``funding_height is None`` **and** ``confirmations == 0``.
      There is no such thing as a mempool UTXO that also names the block it is
      in, nor a mined one with zero depth.
    * confirmed ⇒ ``1 <= funding_height <= tip_height`` and
      ``confirmations == tip_height - funding_height + 1`` — the same identity
      :func:`read_covenant_chain_state` computes.

    This is not bookkeeping. ``read_covenant_chain_state`` derives
    ``confirmations`` by subtraction, so a server reporting a UTXO height ABOVE
    the tip yields a NEGATIVE depth, and negative depth does not fail closed
    everywhere it flows: :func:`build_cold_claim` computes
    ``blocks_to_deadline = max(0, refund_csv - confirmations)``, so a depth of
    ``-4`` against a 20-block CSV reports **24 blocks to the deadline** — more
    headroom than the CSV total, and a *lower* urgency multiplier — to an
    operator racing that deadline with no RBF and no CPFP to fix a slow
    broadcast. Refusing to build the state at all turns a silently optimistic
    number into a stopped run with a readable cause.
    """

    outpoint: str  # "txid:vout"
    carrier_value: int
    funding_height: int | None
    tip_height: int
    confirmations: int

    def __post_init__(self) -> None:
        if self.tip_height < 0:
            raise ValidationError(f"tip_height must be >= 0, got {self.tip_height}")
        if self.funding_height is None:
            if self.confirmations != 0:
                raise ValidationError(
                    f"chain state claims {self.confirmations} confirmations with no funding height. A UTXO "
                    "is either in the mempool (no height, 0 confirmations) or in a block (both) — this "
                    "pair describes neither."
                )
            return
        if self.funding_height < 1:
            raise ValidationError(
                f"funding_height must be >= 1 when set, got {self.funding_height}; use None for a "
                "mempool (0-confirmation) UTXO."
            )
        if self.funding_height > self.tip_height:
            raise ValidationError(
                f"the covenant UTXO reports funding height {self.funding_height} above the chain tip "
                f"{self.tip_height}. That cannot happen on a consistent view — the server is lying, "
                "lagging, or you are pointed at the wrong network. Refusing rather than deriving a "
                "negative confirmation count, which would be reported to you as EXTRA time before the "
                "CSV deadline."
            )
        expected = self.tip_height - self.funding_height + 1
        if self.confirmations != expected:
            raise ValidationError(
                f"confirmations {self.confirmations} does not match tip {self.tip_height} minus funding "
                f"height {self.funding_height} plus one ({expected})."
            )


async def read_covenant_chain_state(client: Any, spk_hex: str) -> CovenantChainState:
    """Locate the live covenant UTXO for ``spk_hex`` and measure its depth.

    Refuses ambiguity rather than guessing: a covenant SPK that holds more than one
    UTXO cannot be resolved to "the" covenant outpoint, and picking one silently could
    build a spend of the wrong output.
    """
    sh = electrumx_script_hash(spk_hex)
    utxos = list(await client.get_utxos(sh))
    tip = int(await client.get_tip_height())
    if not utxos:
        history = await client.get_history(sh)
        raise ValidationError(
            "the covenant SPK holds no unspent output — "
            + (
                "it has chain history, so the swap already settled (claimed or refunded)."
                if history
                else "it was never funded, or you are pointed at the wrong network."
            )
        )
    if len(utxos) > 1:
        raise ValidationError(
            f"the covenant SPK holds {len(utxos)} unspent outputs; cannot resolve a single covenant "
            "outpoint. Inspect them by hand before building a spend."
        )
    u = utxos[0]
    height = int(u.height) if int(u.height) > 0 else None
    return CovenantChainState(
        outpoint=f"{u.tx_hash}:{u.tx_pos}",
        carrier_value=int(u.value),
        funding_height=height,
        tip_height=tip,
        confirmations=(tip - height + 1) if height is not None else 0,
    )


def fee_scriptpubkey(wif: str) -> bytes:
    """The plain P2PKH scriptPubKey the fee key controls.

    Derived, not configured: the fee input must be one the key can sign, so asking the
    operator for its script as well would only create a way to point at the wrong one.
    """
    return b"\x76\xa9\x14" + _pkh_from_wif(wif) + b"\x88\xac"


async def read_fee_utxos(client: Any, wif: str) -> list[Any]:
    """Every unspent output at the fee key's own P2PKH script (a plain read)."""
    return list(await client.get_utxos(electrumx_script_hash(fee_scriptpubkey(wif))))


#: How many times the fee requirement a single input may exceed before it is treated as a
#: mistake rather than a choice. The covenant permits ONE output, so there is no change and the
#: ENTIRE input becomes the miner fee — an operator who points the cold toolkit at an ordinary
#: funded key (one 500 RXD UTXO) was burning ~18,700x the ~2.66M-photon requirement while the
#: CLI reported that the fee "clears the deadline-aware TARGET" (audit B4). 10x leaves generous
#: headroom for a deadline-critical spend and still catches a whole-wallet UTXO by three orders
#: of magnitude. It is a MULTIPLE, not an absolute: a genuinely large requirement scales with it.
MAX_FEE_OVERPAY_MULTIPLE: int = 10


def fee_overpay_ceiling(*, floor: int, target: int) -> int:
    """The largest fee input the cold path will burn without an explicit ``--allow-overpay``."""
    return max(int(floor), int(target)) * MAX_FEE_OVERPAY_MULTIPLE


def fee_overpay_multiple(fee_photons: int, *, floor: int, target: int) -> float:
    """How many times the fee requirement this input actually pays (>= 1.0 is normal)."""
    requirement = max(int(floor), int(target), 1)
    return int(fee_photons) / requirement


def select_fee_utxo(
    utxos: Sequence[Any], *, floor: int, target: int, explicit: str | None, allow_overpay: bool = False
) -> Any:
    """Pick the fee input, or explain exactly why none will do.

    The covenant permits a single output, so there is no change and **the whole fee
    input is the miner fee**. "Choosing the fee" therefore means choosing which UTXO to
    burn, and the default picks the SMALLEST one that still clears the deadline-aware
    target — overshooting is not free here, it is fee paid to a miner.

    Falls back to the smallest input clearing the relay FLOOR when nothing reaches the
    target: the floor is the node's actual requirement, the target is a headroom policy,
    and refusing a spend the node would have accepted is how an operator loses the asset
    to the counterparty's refund (the same reasoning as
    :func:`~pyrxd.gravity.fee_policy.assert_fee_covers`).

    Both ends are bounded. Below the floor the node rejects outright; ABOVE
    :func:`fee_overpay_ceiling` the input is refused as an overpay (audit B4) — the
    dust-floor check in :func:`pyrxd.gravity.htlc_spend._check_carrier` claims to guard "a
    mistakenly-huge UTXO" but only ever checked the small end. ``allow_overpay=True`` is the
    deliberate override, and it applies to an explicitly named ``--fee-utxo`` too: naming a
    UTXO by hand is not consent to burn 500 RXD on a 0.0266 RXD fee.
    """
    ceiling = fee_overpay_ceiling(floor=floor, target=target)

    def _reject_overpay(value: int, *, chosen_by: str) -> ValidationError:
        return ValidationError(
            f"OVERPAY refused: the {chosen_by} fee input is {value} photons against a requirement of "
            f"~{max(int(floor), int(target))} photons ({value / max(int(floor), int(target), 1):.0f}x). The "
            "covenant permits ONE output, so there is no change — the ENTIRE input is paid to the miner. "
            f"Carve a fee UTXO under ~{ceiling} photons, or pass --allow-overpay to burn this one deliberately."
        )

    if explicit is not None:
        want = parse_outpoint(explicit, what="--fee-utxo")
        for u in utxos:
            if u.tx_hash == want.txid and int(u.tx_pos) == want.vout:
                if int(u.value) > ceiling and not allow_overpay:
                    raise _reject_overpay(int(u.value), chosen_by="requested")
                return u
        raise ValidationError(
            f"--fee-utxo {explicit} is not an unspent output of the fee key. "
            f"Available: {', '.join(f'{u.tx_hash}:{u.tx_pos}={u.value}ph' for u in utxos) or '(none)'}"
        )
    if not utxos:
        raise ValidationError("the fee key has no unspent outputs; fund it before building a cold spend")
    by_value = sorted(utxos, key=lambda u: int(u.value))
    in_band = by_value if allow_overpay else [u for u in by_value if int(u.value) <= ceiling]
    for u in in_band:
        if int(u.value) >= target:
            return u
    for u in in_band:
        if int(u.value) >= floor:
            return u
    biggest = int(by_value[-1].value)
    if biggest > ceiling:
        # There IS an input that clears the floor — it is just absurdly large. Say that,
        # rather than the misleading "no fee input clears the relay floor".
        raise _reject_overpay(biggest, chosen_by="only available")
    raise ValidationError(
        f"no fee input clears the relay floor: the largest available is {biggest} photons, the floor is "
        f"~{floor} photons. Radiant has no RBF and no CPFP, so an under-fee'd spend cannot be bumped — "
        "fund a larger fee UTXO rather than broadcasting this."
    )


# --------------------------------------------------------------------------- covenant rebuild


def rebuild_covenant(
    *,
    asset_variant: str,
    taker_pkh: bytes,
    maker_pkh: bytes,
    hashlock: bytes,
    refund_csv: int,
    amount: int,
    genesis_ref: str | None = None,
) -> HtlcCovenant:
    """Rebuild the funded :class:`HtlcCovenant` from public parameters.

    The covenant is not stored anywhere — only its scriptPubKey is — so the cold path
    must reconstruct it to spend it. That reconstruction is SELF-CHECKING: the caller
    compares the rebuilt ``funded_spk`` against the persisted one
    (:func:`assert_covenant_matches`), so a wrong amount, a wrong pkh or a drifted
    timelock fails loudly instead of producing a spend of some other covenant.
    """
    if asset_variant not in ("rxd", "ft", "nft"):
        # Checked FIRST so a typo'd variant reports the typo, not a confusing complaint
        # about a genesis ref the operator was never going to be asked for.
        raise ValidationError(f"unknown asset variant {asset_variant!r} (expected rxd|ft|nft)")
    if asset_variant == "rxd":
        return build_htlc_covenant_rxd(
            amount=amount, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=hashlock, refund_csv=refund_csv
        )
    if genesis_ref is None:
        raise ValidationError(f"{asset_variant} covenants need the asset genesis ref ('txid:vout')")
    ref = parse_outpoint(genesis_ref, what="genesis ref")
    if asset_variant == "ft":
        return build_htlc_covenant_ft(
            genesis_txid=ref.txid,
            genesis_vout=ref.vout,
            amount=amount,
            taker_pkh=taker_pkh,
            maker_pkh=maker_pkh,
            hashlock=hashlock,
            refund_csv=refund_csv,
        )
    return build_htlc_covenant_nft(
        genesis_txid=ref.txid,
        genesis_vout=ref.vout,
        nft_carrier_value=amount,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        hashlock=hashlock,
        refund_csv=refund_csv,
    )


def assert_covenant_matches(covenant: HtlcCovenant, expected_spk_hex: str) -> None:
    """Fail closed unless the rebuilt covenant IS the one the recovery file recorded."""
    if covenant.funded_spk.hex() != expected_spk_hex.lower():
        raise ValidationError(
            "the rebuilt covenant scriptPubKey does not match the one in the recovery file — one of the "
            "rebuild inputs is wrong (covenant amount, taker/maker pkh, hashlock, t_rxd, or genesis ref). "
            "Refusing to build a spend against a covenant this is not."
        )


# --------------------------------------------------------------------------- cold spends


@dataclass(frozen=True)
class ColdSpend:
    """A built-but-NEVER-broadcast covenant spend, with everything a human needs to judge it."""

    kind: str  # "claim" | "refund"
    raw_hex: str
    txid: str
    size_bytes: int
    covenant_outpoint: str
    carrier_value: int
    fee_outpoint: str
    fee_photons: int
    relay_floor_photons: int
    target_photons: int
    urgency_multiplier: float
    blocks_to_deadline: int | None
    clears_floor: bool
    clears_target: bool
    csv_required: int
    csv_confirmations: int
    csv_mature: bool
    outputs: tuple[dict[str, Any], ...]
    #: fee paid / fee required. The whole input is the fee, so this is the real overpay factor.
    overpay_multiple: float = 1.0
    #: True when the fee exceeds :func:`fee_overpay_ceiling` — reachable only via --allow-overpay.
    is_overpay: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "txid": self.txid,
            "raw_hex": self.raw_hex,
            "size_bytes": self.size_bytes,
            "covenant_outpoint": self.covenant_outpoint,
            "carrier_value_photons": self.carrier_value,
            "fee_outpoint": self.fee_outpoint,
            "fee_photons": self.fee_photons,
            "relay_floor_photons": self.relay_floor_photons,
            "target_photons": self.target_photons,
            "urgency_multiplier": self.urgency_multiplier,
            "blocks_to_deadline": self.blocks_to_deadline,
            "clears_floor": self.clears_floor,
            "clears_target": self.clears_target,
            "csv_required": self.csv_required,
            "csv_confirmations": self.csv_confirmations,
            "csv_mature": self.csv_mature,
            "outputs": list(self.outputs),
            "overpay_multiple": self.overpay_multiple,
            "is_overpay": self.is_overpay,
            "broadcast": False,
        }


def _decode_outputs(tx: Any, covenant: HtlcCovenant, kind: str) -> tuple[dict[str, Any], ...]:
    """Decode the built transaction's outputs and NAME each pinned destination.

    The covenant enforces exactly one output whose script it pins by ``hash256``, so the
    operator's real check is "does output[0] pay the party I think it does". Labelling
    it against the rebuilt holder scripts turns that from a hash comparison into
    something a human can actually verify at a glance.
    """
    expected = covenant.taker_holder_script if kind == "claim" else covenant.maker_holder_script
    who = "TAKER" if kind == "claim" else "MAKER"
    out: list[dict[str, Any]] = []
    for i, o in enumerate(tx.outputs):
        spk = bytes(o.locking_script.serialize())
        out.append(
            {
                "index": i,
                "value_photons": int(o.satoshis),
                "scriptpubkey_hex": spk.hex(),
                "pays": f"{who} holder script (pinned by the covenant)" if spk == expected else "UNEXPECTED SCRIPT",
            }
        )
    return tuple(out)


def _fee_input_from(wif: str, utxo: Any) -> FeeInput:
    """Build the :class:`FeeInput` for the fee key's own P2PKH output."""
    pkh = _pkh_from_wif(wif)
    return FeeInput(
        txid=str(utxo.tx_hash),
        vout=int(utxo.tx_pos),
        value=int(utxo.value),
        scriptpubkey=b"\x76\xa9\x14" + pkh + b"\x88\xac",
        wif=wif,
    )


def _measure(
    tx: Any,
    fee: FeeInput,
    policy: DeadlineFeePolicy,
    *,
    blocks_to_deadline: int | None,
) -> tuple[int, int, int, float]:
    """``(size, floor, target, multiplier)`` for the ASSEMBLED transaction.

    Sized against ``len(tx.serialize())`` — the exact wire bytes after signing, which is
    what ``AcceptToMemoryPool`` measures (``GetTotalSize``), never an estimate.
    """
    size = len(tx.serialize())
    return (
        size,
        policy.min_relay_fee(size),
        policy.required_fee(size, blocks_to_deadline=blocks_to_deadline),
        policy.urgency_multiplier(blocks_to_deadline),
    )


def _assert_covenant_confirmed(chain: CovenantChainState, *, allow_unconfirmed: bool, kind: str) -> None:
    """Refuse to build against a covenant that is only in the mempool (audit B5).

    ElectrumX ``listunspent`` returns UNCONFIRMED outputs, so
    :func:`read_covenant_chain_state` happily resolves a 0-conf covenant and the cold builders
    exited 0 against it. A spend of an unconfirmed parent dies with that parent: if the funding
    is conflicted out (or simply never mines), the child is unrelayable, and with neither RBF
    nor CPFP on Radiant its own fee input is then squatted on until the 8h mempool expiry —
    inside the ``t_rxd`` window this claim exists to beat. The automated path already enforces
    this (``radiant_leg.RadiantCovenantLeg._resolve_covenant``); the cold path is now the same.
    """
    if chain.confirmations >= 1 or allow_unconfirmed:
        return
    raise ValidationError(
        f"the covenant funding is UNCONFIRMED (0 confirmations, mempool only) — refusing to build a cold "
        f"{kind}. A spend of an unconfirmed parent dies with it, and Radiant has neither RBF nor CPFP, so "
        "the fee input would then squat until the 8h mempool expiry. Wait for at least one confirmation, "
        "or pass --allow-unconfirmed if you understand that this spend is only as good as its parent."
    )


def build_cold_claim(
    *,
    covenant: HtlcCovenant,
    chain: CovenantChainState,
    preimage: bytes,
    fee_wif: str,
    fee_utxo: Any,
    policy: DeadlineFeePolicy | None = None,
    allow_unconfirmed: bool = False,
) -> ColdSpend:
    """Build (never broadcast) the TAKER's claim spend and measure it against the deadline.

    ``blocks_to_deadline`` is ``t_rxd - confirmations``: the maker's CSV refund branch
    opens once the covenant is ``t_rxd`` deep, so that is the number of Radiant blocks in
    which this claim must be **mined**, not merely broadcast. Clamped at 0 — a deadline
    already passed takes the maximum premium, never a negative one.

    Refuses a 0-conf (mempool-only) covenant unless ``allow_unconfirmed`` — see
    :func:`_assert_covenant_confirmed`.
    """
    pol = policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    _assert_covenant_confirmed(chain, allow_unconfirmed=allow_unconfirmed, kind="claim")
    fee = _fee_input_from(fee_wif, fee_utxo)
    tx = build_htlc_claim_tx(
        covenant=covenant,
        covenant_outpoint=chain.outpoint,
        carrier_value=chain.carrier_value,
        preimage=bytes(preimage),
        fee=fee,
        fee_policy=pol,
    )
    blocks_to_deadline = max(0, covenant.refund_csv - chain.confirmations)
    size, floor, target, mult = _measure(tx, fee, pol, blocks_to_deadline=blocks_to_deadline)
    return ColdSpend(
        kind="claim",
        raw_hex=tx.serialize().hex(),
        txid=tx.txid(),
        size_bytes=size,
        covenant_outpoint=chain.outpoint,
        carrier_value=chain.carrier_value,
        fee_outpoint=f"{fee.txid}:{fee.vout}",
        fee_photons=fee.value,
        relay_floor_photons=floor,
        target_photons=target,
        urgency_multiplier=mult,
        blocks_to_deadline=blocks_to_deadline,
        clears_floor=fee.value >= floor,
        clears_target=fee.value >= target,
        csv_required=covenant.refund_csv,
        csv_confirmations=chain.confirmations,
        csv_mature=chain.confirmations >= covenant.refund_csv,
        outputs=_decode_outputs(tx, covenant, "claim"),
        overpay_multiple=fee_overpay_multiple(fee.value, floor=floor, target=target),
        is_overpay=fee.value > fee_overpay_ceiling(floor=floor, target=target),
    )


def build_cold_refund(
    *,
    covenant: HtlcCovenant,
    chain: CovenantChainState,
    fee_wif: str,
    fee_utxo: Any,
    policy: DeadlineFeePolicy | None = None,
    allow_immature: bool = False,
    allow_unconfirmed: bool = False,
) -> ColdSpend:
    """Build (never broadcast) the MAKER's CSV refund spend.

    ``blocks_to_deadline=None`` — no urgency premium. Unlike the claim, the CSV refund
    has no CLOSING window: it becomes broadcastable at maturity and stays valid
    indefinitely, and the competing claim branch needs ``p``, which on this path the
    counterparty has not revealed. A premium would burn fee for urgency that does not
    exist; the relay floor still binds.

    ``allow_immature`` exists because pre-building before maturity is a legitimate cold
    workflow (assemble and inspect now, broadcast the moment the CSV opens). It is off
    by default so an operator cannot broadcast a non-final refund by accident — with no
    RBF, that transaction would then squat on the covenant for up to 8 hours.

    ``allow_immature`` is about the CSV, NOT about the parent's existence on-chain: a 0-conf
    covenant is still refused unless ``allow_unconfirmed`` is also passed.
    """
    pol = policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    _assert_covenant_confirmed(chain, allow_unconfirmed=allow_unconfirmed, kind="refund")
    mature = chain.confirmations >= covenant.refund_csv
    if not mature and not allow_immature:
        raise ValidationError(
            f"the covenant's CSV refund is not yet mature: it needs {covenant.refund_csv} confirmations "
            f"and has {chain.confirmations} ({covenant.refund_csv - chain.confirmations} block(s) to go). "
            "A node would reject this spend as non-final. Pass --allow-immature to pre-build it anyway "
            "(build now, broadcast at maturity) — but do NOT broadcast it before then."
        )
    fee = _fee_input_from(fee_wif, fee_utxo)
    tx = build_htlc_refund_tx(
        covenant=covenant,
        covenant_outpoint=chain.outpoint,
        carrier_value=chain.carrier_value,
        fee=fee,
        fee_policy=pol,
    )
    size, floor, target, mult = _measure(tx, fee, pol, blocks_to_deadline=None)
    return ColdSpend(
        kind="refund",
        raw_hex=tx.serialize().hex(),
        txid=tx.txid(),
        size_bytes=size,
        covenant_outpoint=chain.outpoint,
        carrier_value=chain.carrier_value,
        fee_outpoint=f"{fee.txid}:{fee.vout}",
        fee_photons=fee.value,
        relay_floor_photons=floor,
        target_photons=target,
        urgency_multiplier=mult,
        blocks_to_deadline=None,
        clears_floor=fee.value >= floor,
        clears_target=fee.value >= target,
        csv_required=covenant.refund_csv,
        csv_confirmations=chain.confirmations,
        csv_mature=mature,
        outputs=_decode_outputs(tx, covenant, "refund"),
        overpay_multiple=fee_overpay_multiple(fee.value, floor=floor, target=target),
        is_overpay=fee.value > fee_overpay_ceiling(floor=floor, target=target),
    )
