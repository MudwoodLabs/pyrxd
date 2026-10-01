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
  ``get_tip_height`` / ``get_transaction`` only.
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
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pyrxd.base58 import base58check_decode
from pyrxd.btc_wallet.taproot import (
    BtcOutpoint,
    btc_input_outpoints_from_raw,
    btc_txid_from_raw,
    scrape_secret,
)
from pyrxd.eth_wallet.secret import recover_secret
from pyrxd.fee_sizing import MAX_FEE_OVERPAY_MULTIPLE as MAX_FEE_OVERPAY_MULTIPLE  # re-export
from pyrxd.fee_sizing import fee_overpay_ceiling, fee_overpay_multiple
from pyrxd.gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY, DeadlineFeePolicy
from pyrxd.gravity.htlc_covenant import (
    HtlcCovenant,
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.keys import PrivateKey
from pyrxd.network.redaction import redact_endpoint_secrets as redact_endpoint_secrets  # re-export
from pyrxd.network.source_identity import canonical_host
from pyrxd.script.script import Script

# ``_looks_like_mnemonic`` is private to ``security.errors`` but is THE definition of
# "this string is a seed phrase" in this SDK, and the gate below must agree with the
# redactor rather than grow a second, drifting copy of the test. Reached by name for the
# same reason ``load_recovery_json`` reaches ``cli_secrets._tighten_hint``.
from pyrxd.security.errors import KeyMaterialError, RxdSdkError, ValidationError, _looks_like_mnemonic
from pyrxd.transaction.transaction import Transaction
from pyrxd.utils import decode_wif

logger = logging.getLogger(__name__)

#: Extra ``get_tip_height`` reads attempted when the tip a first read returned is BELOW
#: the funding height the UTXO read reported. Two, not one: with per-call failover the
#: first re-read can land on the same lagging endpoint that caused the disagreement.
_TIP_REREAD_ATTEMPTS = 2

__all__ = [
    "ETH_READ_ONLY_RPC_METHODS",
    "ColdSpend",
    "CounterLegInconclusive",
    "CounterLegStatus",
    "CovenantChainState",
    "CovenantSpend",
    "PreimageNotRevealed",
    "PreimageRecovery",
    "ProvenanceRefused",
    "RecoveryExtras",
    "RefundReportedUnconfirmed",
    "VerifiedEthTx",
    "WrongEthChain",
    "assert_covenant_matches",
    "build_cold_claim",
    "build_cold_refund",
    "classify_covenant_spend_input",
    "covenant_pkhs",
    "describe_network_error",
    "electrumx_script_hash",
    "electrumx_urls",
    "endpoint_source_label",
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
    "read_covenant_spend",
    "read_eth_counter_leg",
    "read_fee_utxos",
    "rebuild_covenant",
    "recover_preimage_from_btc_claim",
    "recover_preimage_from_eth_artifacts",
    "recover_preimage_from_eth_claim",
    "recover_preimage_from_eth_logs",
    "redact_endpoint_secrets",
    "select_fee_utxo",
    "spent_spender_unknown_reason",
    "verify_raw_eth_tx",
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


class CounterLegInconclusive(ValidationError):
    """The counter-chain read produced NO evidence either way — not "locked", not "not revealed".

    Distinct from :class:`PreimageNotRevealed` because the two call for opposite actions. "Not
    revealed" tells a taker to keep watching; an absence of evidence must not, because the
    commonest way to get an empty answer for a CLAIMED contract is a node that does not serve
    the log history (pruning, or a log-range limit) — and a taker who keeps watching then can
    lose both legs when the covenant's CSV refund opens.
    """


class RefundReportedUnconfirmed(CounterLegInconclusive):
    """The ETH contract's logs report only ``Refunded()`` — ALWAYS this, from one RPC, never a verdict.

    A refund carries no self-verifying value (a claim does: ``sha256(p) == H``). Everything a refund
    report consists of — the ``Refunded`` log, and the transaction bytes behind it — is one server's
    word, and pyrxd cannot prove from one server that the refund happened. Read as "refunded", it
    drove ``swap status`` to SPENT_NO_PREIMAGE — and, beside a taker claim of the covenant, to
    TAKER_CLAIMED_AND_REFUNDED, telling a MAKER who may still be able to claim the ETH that there is
    nothing left to claim. So it is inconclusive for every decision, however consistent the report.

    Raw signed bytes (:class:`VerifiedEthTx`) do not change that. Their hash and their ``to`` /
    selector are checked against the log, which catches an honest RPC that served the wrong
    transaction (that is a :class:`ProvenanceRefused`), but nothing in them shows the transaction
    was ever broadcast or mined. A server can sign a ``refund()`` call (it takes no argument) with
    any key it holds and name that transaction's hash in a fabricated log; pyrxd does not check that
    a transaction succeeded, so checking its signature or sender would not help. Only a second,
    independent source can.
    """


class WrongEthChain(ValidationError):
    """The ETH RPC is on a different chain than the swap, so nothing it says about the contract counts.

    The same contract address can exist on several EVM chains (a deterministic deployer, or the
    same deployer nonce), and an RPC pointed at the wrong network answers ``eth_getLogs`` for it
    without complaint. Its own error, not :class:`ProvenanceRefused`: the fix is a different RPC
    URL, not a different ``--eth-contract``.
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


#: Field-name fragments that mean "this value is spending authority" — the CHEAP
#: FAST PATH, not the gate.
#:
#: A name list can only ever recognise the names somebody thought of, and this one
#: measurably did not: with a real 52-character WIF as the value, every one of
#: ``{"key": …}``, ``{"signing_key": …}``, ``{"priv": …}``, ``{"taker": …}``,
#: ``{"parties": [wif, wif]}`` (a bare list, no field name at all) and
#: ``{"recovery_phrase": "<12 BIP-39 words>"}`` was judged keyless and accepted at mode
#: 0644. Note ``key_hex`` IS here while a bare ``key`` is not, which is the shape of the
#: problem rather than an oversight to patch: the list cannot be finished. The gate is
#: :func:`_value_is_spending_authority`, which decodes the VALUE and does not care what
#: field it sits in; these fragments only let the common case answer without decoding.
#:
#: ``mnemonic`` / ``seed`` / ``xprv`` are here because a recovery file carrying a
#: mnemonic is carrying EVERY key the wallet will ever derive. A false positive costs
#: one ``chmod``; a false negative costs the keys.
#:
#: Deliberately does NOT list ``"preimage"``: the hashlock preimage ``p`` is published
#: on-chain by the claim that reveals it, so a file carrying only ``p`` is not a key
#: file and demanding 0600 of it would be a spurious refusal on a public document.
_PRIVATE_KEY_MARKERS = (
    "wif",
    "privkey",
    "private_key",
    "key_hex",
    "secret",
    "mnemonic",
    "seed",
    "xprv",
)

#: 64 hex characters — a raw 32-byte value written the way a private key is written.
_BARE_32_BYTE_HEX = re.compile(r"^[0-9a-fA-F]{64}$")

#: Field-name fragments under which a 64-hex value is a PUBLIC 32-byte quantity.
#:
#: This is the one place a NAME still decides anything about a hex value, and it has to,
#: because a 32-byte secret and a 32-byte hash are the same 64 characters. The polarity
#: is the point: this is an allowlist, so an unrecognised field holding 64 hex chars —
#: ``{"k": "<32 bytes of key>"}`` — is treated as a key, and a name nobody thought of
#: fails CLOSED instead of open.
#:
#: Every entry was measured against a writer or a reader in this repository, not
#: guessed:
#:
#: * ``hashlock`` — ``hashlock_H`` / ``hashlock_H_hex``. Required in EVERY recovery file
#:   (``swap_cmds.parse_recovery_file`` refuses a document without it), so without this
#:   entry the 64-hex rule would make every recovery file keyful and the 0644
#:   public-locator workflow that ``--taker-pkh`` / ``--maker-pkh`` exist for would stop
#:   working entirely. Measured on the fixture in ``tests/cli/test_swap_recovery.py``.
#: * ``preimage`` — ``preimage_p_hex``; public by the time it matters, see above.
#: * ``xonly`` — ``btc_claim_xonly_hex`` / ``taker_btc_refund_xonly_hex``
#:   (``scripts/btc_swap_two_host.py``): x-only PUBLIC keys, exactly 64 hex.
#: * ``pubkey`` / ``public_key`` — public keys.
#: * ``txid`` / ``tx_hash`` / ``outpoint`` / ``block_hash`` / ``blockhash`` / ``merkle``
#:   — chain identifiers, all 32-byte hashes.
#: * ``spk`` / ``script`` — scriptPubKeys, which are hex of arbitrary length and can be
#:   64 characters.
_PUBLIC_32_BYTE_FIELD_MARKERS = (
    "hashlock",
    "preimage",
    "xonly",
    "pubkey",
    "public_key",
    "txid",
    "tx_hash",
    "outpoint",
    "block_hash",
    "blockhash",
    "merkle",
    "spk",
    "script",
)


#: Longest string that could still BE a base58check-encoded key, so the longest one
#: worth attempting to decode. A WIF is 51-52 characters; the longest thing this
#: predicate looks for, a BIP-32 extended key (78 payload + 4 checksum bytes), is ~112.
#:
#: This is a bound on work, not on correctness. ``b58_decode`` builds one big integer a
#: character at a time, which is O(n^2): measured on this branch, a single 65 000-char
#: base58-valid string (just inside ``MAX_SECRET_FILE_BYTES``) took **0.65 s** to decode
#: and reject, against 0.012 s for a realistic document of 600 hundred-character fields.
#: Bounded and local, so not a DoS — but there is no reason to pay it, and refusing to
#: even try above this length cannot hide a key, because no key encodes that long.
#: The mnemonic branch is deliberately NOT bounded by it: a 24-word phrase is ~190
#: characters.
_MAX_ENCODED_KEY_CHARS = 128


def _is_wif(text: str) -> bool:
    """True if *text* decodes as a WIF. Broad ``except`` — any failure means "no".

    Split out rather than inlined so the failure path is a ``return`` and not a bare
    ``pass``: this runs inside a security gate and must never raise, and a
    ``try/except/pass`` is both harder to read and what bandit's B110 flags.
    """
    try:
        decode_wif(text)
    except Exception:
        return False
    return True


def _base58check_payload(text: str) -> bytes:
    """The base58check payload of *text*, or empty if it is not base58check."""
    try:
        return base58check_decode(text)
    except Exception:
        return b""


def _value_is_spending_authority(text: str) -> bool:
    """True if *text* IS a private key, decided by DECODING it — never by its name.

    Three tests, in cost order. Each is a decode rather than a shape guess, so a false
    positive needs a public value that is simultaneously a checksum-valid encoding of a
    key, which is not a thing a locator can accidentally be:

    1. **WIF** — :func:`~pyrxd.utils.decode_wif` verifies the base58check checksum AND
       requires a known WIF version byte. A Radiant address is base58check too but
       carries an address version and a 20-byte payload, so it does not pass.
    2. **BIP-32 extended PRIVATE key** — 78 payload bytes with ``0x00`` at index 45.
       That byte is the serialisation's discriminator: an ``xpub``/``tpub`` carries a
       ``0x02``/``0x03`` SEC prefix there, so this matches ``xprv``/``tprv`` (and the
       ``yprv``/``zprv`` variants) without enumerating version bytes.
    3. **BIP-39 mnemonic** — the SDK's own redaction test, so the phrase this refuses to
       leave at 0644 is exactly the phrase :func:`pyrxd.security.errors.redact` refuses
       to print.

    Deliberately NOT here: bare 64-hex. It is handled by :func:`_carries_private_key`
    with the field name in hand, because a 32-byte secret and a 32-byte hash are
    indistinguishable as values — see :data:`_PUBLIC_32_BYTE_FIELD_MARKERS`.
    """
    # Nothing shorter can encode a 32-byte key; skips the ordinary short scalars
    # (``"bc"``, a stage name) without paying for a base58 decode.
    if len(text) < 16:
        return False
    if len(text) <= _MAX_ENCODED_KEY_CHARS:
        if _is_wif(text):
            return True
        raw = _base58check_payload(text)
        if len(raw) == 78 and raw[45] == 0:
            return True
    return _looks_like_mnemonic(text)


def _carries_private_key(value: Any) -> bool:
    """True if *value* holds spending authority ANYWHERE in it, at any depth.

    The gate this feeds asks "does this document hold a key?", and a document holds what
    it holds regardless of where it sits or what the field is called. So every string in
    the structure is DECODED (:func:`_value_is_spending_authority`) rather than judged by
    its field name; the name markers remain only as a fast path for the common case, and
    the one place a name still matters is the bare-64-hex rule, where it is an allowlist
    of public quantities and an unknown name fails closed.

    Iterative, not recursive. The recursive version raised an uncaught
    ``RecursionError`` — surfaced by the CLI as "unexpected failure (RecursionError)" —
    on a ~1 KB file of ~500 nested JSON lists, well inside the 64 KB read bound, while
    ``json.loads`` itself parsed the same file happily. An explicit stack has no depth
    limit to exceed; the node count is bounded by the file-size gate that already ran.

    Truthiness is still required for the name markers, so a present-but-empty
    ``"taker_rxd_wif": ""`` (what a two-host harness writes for the role it does not
    hold) is not a key — that, plus the public-field allowlist, is what keeps this from
    refusing the public-locator workflow the ``--taker-pkh`` / ``--maker-pkh`` flags
    exist for.
    """
    # Each entry is (enclosing field name, node). List items inherit the enclosing name,
    # so ``{"preimages": ["<64 hex>", …]}`` is judged the way ``preimage_p_hex`` is.
    stack: list[tuple[str, Any]] = [("", value)]
    while stack:
        field, node = stack.pop()
        if isinstance(node, dict):
            for key, sub in node.items():
                name = key.lower() if isinstance(key, str) else ""
                if name and sub and any(marker in name for marker in _PRIVATE_KEY_MARKERS):
                    return True
                stack.append((name, sub))
        elif isinstance(node, (list, tuple)):
            stack.extend((field, item) for item in node)
        elif isinstance(node, str) and node:
            if _value_is_spending_authority(node):
                return True
            if _BARE_32_BYTE_HEX.match(node) and not any(m in field for m in _PUBLIC_32_BYTE_FIELD_MARKERS):
                return True
    return False


def load_recovery_json(path: Path) -> dict[str, Any]:
    """Read a recovery file under the same gate its fee-key sibling already gets.

    The asymmetry this closes
    -------------------------
    ``swap build-claim`` took two files. The ``--fee-wif-file`` — ONE key, for fees —
    went through :func:`~pyrxd.gravity.watch.cli_secrets.read_secret_file`: symlink
    refused, ``fstat`` on the read fd, owner-only mode, ownership, bounded size. The
    recovery file — which in a single-operator harness run carries ``taker_rxd_wif``
    AND ``maker_rxd_wif``, i.e. BOTH counterparties' spending keys — was read with a
    bare ``json.loads(path.read_text())``: no mode check, no ownership check, no
    symlink refusal, no size bound.

    The care in this module went into never letting a WIF into an error message
    (:func:`_pkh_from_wif` is meticulous about it) — a leak-on-error defence, with
    nothing behind it about the file those keys sit in at rest. A recovery file left
    at the default 0644 by ``cp``, ``rsync``, an editor's write-new-then-rename, or an
    unzip is world-readable, and nothing told the operator.

    Why the mode check is conditional
    ---------------------------------
    A recovery file is not always a key file. The two-host harnesses persist only
    public locators and pkhs (which is why ``--taker-pkh``/``--maker-pkh`` exist), and
    refusing to read a public file because it is 0644 would be a false alarm on the
    exact workflow the pkh flags were added for. So: read under the always-on half of
    the gate, then require owner-only mode only if the document actually contains a
    key. The mode is ``fstat``-ed from the fd the bytes came from, so judging it after
    parsing is not a check-then-use race.

    Why the path gate is the wallet's and not the watchtower's
    ----------------------------------------------------------
    ``operator_chosen_path=True``. A recovery-file path is typed by a person, like a
    wallet path and unlike a machine-managed watchtower credential, so it allows a
    symlink (external storage is an ordinary place to keep one) and a ROOT-owned file
    (the harnesses run their nodes in Docker; a root-written JSON on a bind mount was
    refused outright, mid-incident, with no override). A file owned by any other
    unprivileged uid is still refused. See
    :func:`~pyrxd.gravity.watch.cli_secrets.read_file_guarded` for why those two checks
    get different answers.

    Raises:
        ValidationError: the file is not a regular file, owned by another unprivileged
            user, oversized, not UTF-8, not JSON, not a JSON object, or carries a
            private key at a group/world-accessible mode.
    """
    # Local import: ``cli_secrets`` is package code with a deliberately small
    # dependency graph, and ``swap_recovery_cmds`` already reaches it this way.
    from ..gravity.watch.cli_secrets import read_file_guarded

    text, mode = read_file_guarded(path, label="recovery file", require_owner_only=False, operator_chosen_path=True)
    try:
        d = json.loads(text)
    except json.JSONDecodeError as exc:
        # ``from None``: JSONDecodeError renders the offending line, and that line
        # may be the one holding a WIF.
        raise ValidationError(f"recovery file {path} is not valid JSON (line {exc.lineno})") from None
    except RecursionError:
        # ``json.loads`` recurses per nesting level. Measured: it parses ~5,000 nested
        # lists and raises at ~16,000, which is 32 KB of ``[`` — half the 64 KB this
        # gate already allows, so the bound above does not exclude it. Uncaught, the CLI
        # renders it as "unexpected failure (RecursionError)" and the operator learns
        # nothing about their file. Fails closed either way; this only says why.
        raise ValidationError(
            f"recovery file {path} is nested too deeply to parse. A recovery file is a flat "
            "JSON object of locators; this is not one."
        ) from None
    if not isinstance(d, dict):
        raise ValidationError("recovery file is not a JSON object")
    if mode is not None and mode & 0o077 and _carries_private_key(d):
        # Action first: `swap_recovery_cmds._load` renders this through
        # ``sanitize_terminal(..., max_len=400)``, so the remedy must survive truncation
        # — and the remedy has to be one that can actually run, which `chmod` is not on
        # read-only media or a root-written bind mount (`_tighten_hint` picks the
        # workable one and leads with it).
        from ..gravity.watch.cli_secrets import _tighten_hint

        raise ValidationError(
            f"recovery file has mode {oct(mode)} and contains a private key — "
            f"{_tighten_hint(path)}. Treat those keys as exposed: at this mode "
            "anyone with an account on this host could already have read them."
        )
    return d


def parse_recovery_extras(path: Path) -> RecoveryExtras:
    """Parse the OPTIONAL locator fields out of a recovery JSON (never any secret).

    Tolerant by design: every field is optional and a missing one simply becomes
    ``None`` so the CLI can ask for it via a flag. It deliberately does NOT read
    ``preimage_p_hex`` — see the module docstring for why that copy is not legitimate.
    """
    d = load_recovery_json(path)
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
    d = load_recovery_json(path)

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


#: ``refund()``'s 4-byte selector, ``keccak256("refund()")[:4]`` — the same in ``EthHtlc.sol`` and
#: ``Erc20Htlc.sol`` (pinned against keccak by ``test_refund_selector_is_keccak_of_the_signature``).
ETH_REFUND_SELECTOR = bytes.fromhex("590e1ae3")

#: Typed-envelope field layouts: ``type -> (index of to, index of data, field count)``.
#: EIP-2930 (1), EIP-1559 (2), EIP-4844 (3, canonical form without the blob sidecar), EIP-7702 (4).
_TYPED_TX_LAYOUT = {1: (4, 6, 11), 2: (5, 7, 12), 3: (5, 7, 14), 4: (5, 7, 13)}
_LEGACY_TX_LAYOUT = (3, 5, 9)
_RLP_MAX_DEPTH = 8  # an access/authorization list nests 3 deep; bounds recursion on hostile bytes


def _keccak256(data: bytes) -> bytes:
    from Cryptodome.Hash import keccak  # pycryptodomex — a base dependency, not the [eth] extra

    return keccak.new(digest_bits=256, data=bytes(data)).digest()


def _rlp_item(data: bytes, pos: int, depth: int = 0) -> tuple[bytes | list[Any], int]:
    """Decode one RLP item at *pos*: ``(item, end)``. Raises ``ValueError`` on anything malformed.

    CANONICAL encodings only, as pyrlp's strict decoder: a single byte below ``0x80`` must be
    encoded as itself (``0x81 0x05`` is refused), and a long-form length must have no leading zero
    and must exceed 55 (anything shorter has a short form). Each value then has exactly one
    encoding, so the bytes pyrxd hashes are the bytes it decoded and no other spelling of them.
    """
    if depth > _RLP_MAX_DEPTH:
        raise ValueError("RLP nested too deeply")
    if pos >= len(data):
        raise ValueError("RLP item runs past the end")
    b0 = data[pos]
    if b0 < 0x80:
        return data[pos : pos + 1], pos + 1
    if b0 < 0xB8 or 0xC0 <= b0 < 0xF8:
        length, start = (b0 - 0x80 if b0 < 0xC0 else b0 - 0xC0), pos + 1
    else:
        len_len = (b0 - 0xB7) if b0 < 0xC0 else (b0 - 0xF7)
        start = pos + 1 + len_len
        if start > len(data):
            raise ValueError("RLP length runs past the end")
        if data[pos + 1] == 0:
            raise ValueError("non-canonical RLP: long-form length with a leading zero")
        length = int.from_bytes(data[pos + 1 : start], "big")
        if length <= 55:
            raise ValueError("non-canonical RLP: long-form length for a payload that has a short form")
    end = start + length
    if end > len(data):
        raise ValueError("RLP payload runs past the end")
    if b0 < 0xC0:
        if length == 1 and data[start] < 0x80:
            raise ValueError("non-canonical RLP: a single byte below 0x80 must encode as itself")
        return data[start:end], end
    items: list[Any] = []
    p = start
    while p < end:
        item, p = _rlp_item(data, p, depth + 1)
        items.append(item)
    if p != end:
        raise ValueError("RLP list items overrun the list")
    return items, end


def _rlp_uint(field: Any, what: str) -> int:
    """A canonical RLP unsigned integer: a byte string with no leading zero (``b""`` is 0)."""
    if not isinstance(field, bytes) or field[:1] == b"\x00":
        raise ValueError(f"malformed {what} field")
    return int.from_bytes(field, "big")


def _decode_eth_tx_fields(raw: bytes) -> tuple[int, bytes, bytes, int | None]:
    """``(tx_type, to, data, chain_id)`` read from a transaction's own bytes (legacy or typed envelope)."""
    if not raw:
        raise ValueError("empty transaction")
    if raw[0] >= 0xC0:
        tx_type, (to_i, data_i, count), body = 0, _LEGACY_TX_LAYOUT, raw
    elif raw[0] in _TYPED_TX_LAYOUT:
        tx_type, body = raw[0], raw[1:]
        to_i, data_i, count = _TYPED_TX_LAYOUT[tx_type]
    else:
        raise ValueError(f"unsupported transaction envelope type 0x{raw[0]:02x}")
    fields, end = _rlp_item(body, 0)
    if end != len(body):
        raise ValueError("trailing bytes after the transaction")
    if not isinstance(fields, list) or len(fields) != count:
        raise ValueError(f"a type-{tx_type} transaction has {count} fields")
    to, data = fields[to_i], fields[data_i]
    if not isinstance(to, bytes) or len(to) not in (0, 20) or not isinstance(data, bytes):
        raise ValueError("malformed to/data field")
    if tx_type:
        chain_id: int | None = _rlp_uint(fields[0], "chainId")
    else:
        v = _rlp_uint(fields[6], "v")
        chain_id = (v - 35) // 2 if v >= 35 else None  # EIP-155; 27/28 is a pre-EIP-155 legacy tx
    return tx_type, to, data, chain_id


@dataclass(frozen=True)
class VerifiedEthTx:
    """An ETH transaction read from its RAW SIGNED BYTES, whose hash pyrxd computed itself.

    Built from RPC data only by :func:`verify_raw_eth_tx`. ``hash`` is ``keccak256(raw)`` and ``to`` /
    ``input`` are decoded from those same bytes, so one cannot be swapped without changing the
    other — unlike ``eth_getTransactionByHash`` JSON, where a server can pair any ``hash`` with any
    ``to`` and ``input``. That makes it a CONSISTENCY check on the server's answer: it catches an
    RPC that served a different transaction than its log names.

    What it does NOT prove: anything about the chain. Its signature, sender and chain id are not
    checked, and checking them would not help — the bytes come from the RPC that served the logs,
    which can sign a ``refund()`` call with any key it holds, never broadcast it, and name its hash in
    a fabricated ``Refunded`` log. So
    an ETH refund read from one RPC is never definitive (:class:`RefundReportedUnconfirmed`).
    """

    hash: str  # 0x-prefixed lower-case keccak256 of the raw bytes
    to: str | None  # 0x-prefixed lower-case address; None for a contract creation
    input: bytes
    tx_type: int
    #: The chain id the transaction's own bytes name (typed: field 0; legacy: EIP-155 ``v``), or
    #: ``None`` for a pre-EIP-155 legacy transaction, which names none.
    chain_id: int | None = None

    def as_claim_dict(self) -> dict[str, Any]:
        """The ``{"hash", "to", "input"}`` shape :func:`recover_preimage_from_eth_claim` reads."""
        return {"hash": self.hash, "to": self.to, "input": "0x" + self.input.hex()}

    def is_refund_call_to(self, contract_address: str) -> bool:
        """True iff this transaction calls ``refund()`` on *contract_address* (read from its bytes)."""
        return _same_address(self.to, contract_address) and self.input[:4] == ETH_REFUND_SELECTOR


def verify_raw_eth_tx(raw: bytes | str, expected_hash: str) -> VerifiedEthTx:
    """Hash and decode a raw signed ETH transaction; refuse it unless it IS *expected_hash*. Pure.

    Raises
    ------
    ProvenanceRefused
        ``keccak256(raw)`` is not *expected_hash* (the server served a different transaction), or
        the bytes are not a transaction pyrxd can decode.
    """
    blob = _hex_blob(raw) if isinstance(raw, str) else bytes(raw)
    computed = "0x" + _keccak256(blob).hex()
    if not blob or not _same_address(computed, expected_hash):
        raise ProvenanceRefused(
            f"the raw transaction the RPC returned hashes to {computed}, not the requested {expected_hash!r} — "
            "the RPC served a different transaction; refusing to read it"
        )
    try:
        tx_type, to, data, chain_id = _decode_eth_tx_fields(blob)
    except ValueError as exc:
        raise ProvenanceRefused(f"the raw transaction {computed} does not decode: {exc}") from exc
    return VerifiedEthTx(
        hash=computed, to=("0x" + to.hex()) if to else None, input=data, tx_type=tx_type, chain_id=chain_id
    )


def _bound_logs(logs: Sequence[Any], contract_address: str) -> list[dict[str, Any]]:
    """The logs emitted BY the per-swap contract — the ETH analogue of the funding-outpoint bind."""
    return [lg for lg in logs if isinstance(lg, dict) and _same_address(lg.get("address"), contract_address)]


def _fetched_tx_hash(logs: Sequence[Any], contract_address: str) -> str | None:
    """The hash of the transaction :func:`fetch_eth_claim_artifacts` asks for: the LAST bound log's."""
    bound = _bound_logs(logs, contract_address)
    tx_hash = bound[-1].get("transactionHash") if bound else None
    return tx_hash if isinstance(tx_hash, str) else None


def _log_topic0(log: dict[str, Any]) -> str | None:
    """The lower-case 0x-hex of a log's first topic (its event selector), or ``None``."""
    topics = log.get("topics") or []
    if not isinstance(topics, list) or not topics:
        return None
    blob = _hex_blob(topics[0])
    return "0x" + blob.hex() if blob else None


def recover_preimage_from_eth_logs(
    *, hashlock: bytes, contract_address: str, logs: Sequence[dict[str, Any]]
) -> PreimageRecovery:
    """Scrape ``p`` from the contract's OWN logs. Pure — and independent of any tx lookup.

    The contract emits ``Claimed(bytes32 preimage)`` with ``p`` in the log ``data``, so a log
    that has already been fetched carries the preimage by itself. This used to be reachable only
    through :func:`recover_preimage_from_eth_claim`, which needs the transaction too: when the
    ``eth_getTransactionByHash`` lookup came back null (a node that serves logs but not that
    transaction), ``swap status`` reported the leg LOCKED and ``recover-preimage`` said "no
    preimage has been revealed yet" — with ``p`` sitting in a log already in hand.

    Provenance is the per-swap contract address (only logs emitted BY it are scanned), and the
    value is re-verified as ``sha256(p) == H`` before it is returned. A log that merely LOOKS like
    a claim but carries no value hashing to ``H`` is never returned as the preimage.

    Raises
    ------
    PreimageNotRevealed
        No log bound to the contract carries a value hashing to ``H``.
    """
    if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
        raise ValidationError("hashlock must be 32 bytes")
    if not isinstance(contract_address, str) or not contract_address:
        raise ValidationError("contract_address is required for ETH preimage provenance")
    for lg in _bound_logs(logs, contract_address):
        blobs = [_hex_blob(lg.get("data"))]
        topics = lg.get("topics")
        if isinstance(topics, list):
            blobs.extend(_hex_blob(t) for t in topics)
        try:
            p = recover_secret(blobs, bytes(hashlock))
        except (ValidationError, ValueError):
            continue
        _verify_hashes_to(p, bytes(hashlock))
        tx_hash = lg.get("transactionHash")
        return PreimageRecovery(
            preimage_hex=bytes(p).hex(),
            hashlock_hex=bytes(hashlock).hex(),
            counter_chain="eth",
            source="eth_claim_log_data",
            claim_txid=tx_hash if isinstance(tx_hash, str) else None,
            provenance=(
                f"log emitted by our per-swap HTLC contract {contract_address}",
                "sha256(p) == H re-verified independently of the scraper",
            ),
        )
    raise PreimageNotRevealed(f"no log emitted by {contract_address} carries a value hashing to the swap's hashlock")


def recover_preimage_from_eth_artifacts(
    *,
    hashlock: bytes,
    contract_address: str,
    claim_tx: dict[str, Any] | VerifiedEthTx | None,
    logs: Sequence[dict[str, Any]],
    source: str,
) -> PreimageRecovery:
    """Decide the ETH counter-leg from ``(claim_tx, logs)`` — the ONE function both commands use.

    ``swap status`` and ``recover-preimage`` used to decide this separately, and both read a null
    transaction as "no claim". In order:

    1. **No logs and no transaction** — :class:`CounterLegInconclusive`. An unclaimed contract
       returns no logs, but so does a pruned node or a log-range limit for a CLAIMED one; an
       empty answer is not evidence the leg is locked.
    2. **A log already carries p** — returned, verified, whether or not the transaction lookup
       succeeded (:func:`recover_preimage_from_eth_logs`).
    3. **A ``Claimed`` event whose value does not hash to H** — :class:`ProvenanceRefused`. The
       swap's own contract only emits ``Claimed`` for a preimage of ITS hashlock, so this is the
       wrong contract for this swap or a server that is not telling the truth. Never shown as p.
    4. **``Refunded()`` events naming more than one transaction** — :class:`ProvenanceRefused`.
       The contract settles once (``AlreadySettled``), so this RPC's answer contradicts itself.
    5. **The transaction is in hand** — the calldata path, :func:`recover_preimage_from_eth_claim`,
       with the transaction's hash checked against the one requested (the last bound log's).
    6. **Only ``Refunded()`` events** — :class:`RefundReportedUnconfirmed`, ALWAYS. One RPC's refund
       report is that server's word and pyrxd cannot prove it, whatever came with the log: no
       transaction, transaction JSON, or raw signed bytes that hash to the log's transaction and
       decode to a ``refund()`` call to the contract. Those checks are CONSISTENCY checks (a
       mismatch is :class:`ProvenanceRefused` above); passing them never makes a refund definitive.
    7. **Anything else** (logs that carry no p, transaction not retrievable) —
       :class:`CounterLegInconclusive`.

    It never raises :class:`PreimageNotRevealed`: on ETH, "spent without revealing p" is never
    reached from one RPC's answer.
    """
    from pyrxd.gravity.watch.eth_adapters import CLAIMED_TOPIC0, REFUNDED_TOPIC0

    bound = _bound_logs(logs, contract_address)
    if not bound and claim_tx is None:
        raise CounterLegInconclusive(
            f"{source} returned NO logs from the HTLC contract {contract_address}. An unclaimed contract "
            "looks like that, but so does a CLAIMED one read through a pruned node or a log-range limit, "
            "so this is NOT evidence the leg is locked or that p is unrevealed. Re-check against an RPC "
            "that serves the contract's full log history before relying on it."
        )
    try:
        return recover_preimage_from_eth_logs(hashlock=hashlock, contract_address=contract_address, logs=bound)
    except PreimageNotRevealed:
        pass
    topic0s = [_log_topic0(lg) for lg in bound]
    if CLAIMED_TOPIC0 in topic0s:
        raise ProvenanceRefused(
            f"the HTLC contract {contract_address} emitted a Claimed event, but no value in it hashes to this "
            "swap's hashlock H. This swap's own contract can only emit Claimed for a preimage of H, so this is "
            "the wrong contract address for this swap, or the RPC is not telling the truth. Nothing was taken "
            "as the preimage."
        )
    only_refunded = bool(bound) and all(t == REFUNDED_TOPIC0 for t in topic0s)
    refund_txs = (
        {h.lower() for lg in bound if isinstance(h := lg.get("transactionHash"), str)} if only_refunded else set()
    )
    if len(refund_txs) > 1:
        raise ProvenanceRefused(
            f"{source} reports Refunded() from {contract_address} in {len(refund_txs)} different transactions. The "
            "per-swap contract settles once, so this answer contradicts itself: the RPC is wrong or not telling "
            "the truth. Nothing was concluded; read the contract on another RPC or an explorer."
        )
    unverified = "did not return the transaction"
    if claim_tx is not None:
        verified = claim_tx if isinstance(claim_tx, VerifiedEthTx) else None
        try:
            return recover_preimage_from_eth_claim(
                hashlock=hashlock,
                contract_address=contract_address,
                claim_tx=verified.as_claim_dict() if verified is not None else claim_tx,
                logs=logs,
                reported_tx_hash=_fetched_tx_hash(logs, contract_address),
            )
        except PreimageNotRevealed:
            # NEVER definitive from one RPC (round 4): even raw bytes that hash to the log's
            # transaction and decode to refund() on this contract are bytes this server chose.
            if verified is not None and verified.is_refund_call_to(contract_address):
                unverified = (
                    f"its transaction {verified.hash} is consistent with the log (the raw bytes hash to it and "
                    "decode to a refund() call to the contract) — but that is still this one server's word: "
                    "pyrxd cannot prove from one RPC that the transaction was ever broadcast or mined"
                )
            elif verified is None:
                unverified = (
                    "returned the transaction only as JSON, whose hash field pyrxd cannot check against its "
                    "contents (no raw signed bytes from eth_getRawTransactionByHash)"
                )
            else:
                unverified = f"returned transaction {verified.hash}, which is not a refund() call to the contract"
    if only_refunded:
        raise RefundReportedUnconfirmed(
            f"{source} reports only Refunded() from {contract_address}, and {unverified}, so the refund is "
            "UNCONFIRMED (one server's report of a refund proves nothing). Check the contract on a second, "
            "independent ETH RPC or an explorer; MAKER: if the contract still holds the ETH, you can still claim it."
        )
    raise CounterLegInconclusive(
        f"{source} returned {len(bound)} log(s) from the HTLC contract {contract_address}; none carries a "
        "value hashing to H and the transaction that emitted them could not be retrieved, so whether p "
        "is public is UNKNOWN — not 'locked'. Re-check against another RPC."
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
        "eth_getRawTransactionByHash",
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
    # NOT_CHECKED | LOCKED | CLAIMED_PREIMAGE_REVEALED | SPENT_NO_PREIMAGE | REFUND_REPORTED_UNCONFIRMED
    # | UNKNOWN | ERROR. REFUND_REPORTED_UNCONFIRMED (ETH): what EVERY refund report from one RPC is —
    # one server's word, whatever transaction bytes came with it. NOT resolved; swap status treats it
    # like UNKNOWN for every decision. SPENT_NO_PREIMAGE is never produced for ETH.
    state: str
    reason: str
    claim_txid: str | None = None
    preimage_available: bool = False
    #: The ONE server the state came from, by host (:func:`endpoint_source_label`), or
    #: ``None`` when nothing was read. ``swap status`` names it wherever a verdict rests on
    #: that server's word — a SETTLED swap included, not only a LOCKED one.
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain,
            "state": self.state,
            "reason": self.reason,
            "claim_txid": self.claim_txid,
            "preimage_available": self.preimage_available,
            "source": self.source,
        }


def not_checked(chain: str, reason: str) -> CounterLegStatus:
    """The counter-leg was not read, and WHY — reported, never raised.

    A missing endpoint is a configuration fact, not a failure: ``swap status`` must
    still print the RXD covenant verdict it did obtain. Failing the whole command
    because the optional half was unconfigured would be strictly worse for an operator
    who is mid-incident.
    """
    return CounterLegStatus(chain=chain, state="NOT_CHECKED", reason=reason)


def endpoint_source_label(url: str) -> str:
    """Name the ONE server an answer came from, for operator-facing text.

    The canonical host (:func:`pyrxd.network.source_identity.canonical_host`, the spelling
    every source count keys through), never the full URL: an RPC URL routinely carries an API
    key in its path or query. Deliberately NOT :func:`~pyrxd.network.source_identity.source_key`,
    which keys an unparseable URL by its whole text; printing that could print the key.
    """
    try:
        raw = urlsplit(url).hostname or ""
    except ValueError:
        raw = ""
    host = canonical_host(raw) if raw else ""
    return host or "an endpoint whose URL has no parseable host"


def electrumx_urls(ctx: Any) -> tuple[str, ...]:
    """Every ElectrumX URL a CLI context may read through — for :func:`redact_endpoint_secrets`.

    The failover client may have answered from any configured endpoint, not only the primary
    ``electrumx_url``, so all of them are scrubbed. Best-effort: a context with no resolvable
    profile still yields its primary URL.
    """
    urls = [getattr(ctx, "electrumx_url", "") or ""]
    try:
        urls += list(ctx.config.require_profile().urls)
    except Exception:  # nosec B110 - no profile means nothing further to scrub
        pass
    return tuple(u for u in urls if u)


def describe_network_error(exc: BaseException, url: str | None = None, *, scrub: Sequence[str | None] = ()) -> str:
    """Render an exception from a network call WITHOUT the URL it was raised for.

    THE one rendering for every place the swap CLI prints a failed chain read. aiohttp's
    ``ClientResponseError`` renders as ``401, message='Unauthorized', url='https://host/<key>?…'``,
    so printing ``{exc}`` put the operator's keyed ``--eth-rpc-url`` / ``--btc-api-url`` into
    ``swap status`` (human and ``--json``) and into ``recover-preimage``'s error. This renders the
    exception TYPE, its HTTP status when it has one, and the host (:func:`endpoint_source_label`)
    — never the URL. Text from a library exception is dropped entirely: it is not ours, so it
    cannot be known not to quote the URL. Text from pyrxd's own exceptions is kept (it carries the
    useful part, e.g. an RPC's "query returned more than 10000 results") but still passed through
    :func:`redact_endpoint_secrets`, because it can wrap a library message or echo an RPC body.

    ``url`` is the endpoint the call was made to (named by host); ``scrub`` lists any further
    URLs whose secrets must not appear (e.g. every ElectrumX endpoint a failover client may have
    used).
    """
    text = type(exc).__name__
    status = getattr(exc, "status", None)
    if isinstance(status, int) and not isinstance(status, bool):
        text += f" (HTTP {status})"
    if url:
        text += f" from {endpoint_source_label(url)}"
    if isinstance(exc, RxdSdkError):
        detail = redact_endpoint_secrets(str(exc), [url, *scrub])
        if detail:
            text += f": {detail}"
    return text


async def fetch_btc_claim_bytes(
    session: Any, base_url: str, funding_outpoint: BtcOutpoint, *, timeout_s: float = 15.0
) -> tuple[bool, str | None, bytes | None]:
    """Esplora GET pair: ``(spent, spender_txid, raw_bytes)`` for a funding outpoint.

    Three shapes, and callers must tell all three apart:

    * ``(False, None, None)`` — the server says UNSPENT.
    * ``(True, None, None)`` — the server says SPENT but gave no well-formed spending
      txid. The spend exists and cannot be fetched or verified. This is NOT unspent: it
      used to be returned as ``(False, None, None)``, so an explorer answering
      ``{"spent": true}`` with the txid missing or malformed made both ``swap status``
      and ``recover-preimage`` report the counterparty had not claimed — the one
      answer that tells a taker to keep waiting while ``p`` may already be public.
    * ``(True, txid, raw_or_None)`` — spent by ``txid``; ``raw`` is ``None`` when the
      bytes are not retrievable yet.

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
    if not spent:
        return False, None, None
    if not spender:
        return True, None, None
    raw = await mempool_space_tx_hex(session, base_url, spender, timeout_s=timeout_s)
    return True, spender, raw


def spent_spender_unknown_reason(source: str, funding_outpoint: BtcOutpoint) -> str:
    """The operator text for ``(True, None, None)`` — shared so both commands say the same thing."""
    return (
        f"{source} reports the BTC funding outpoint {funding_outpoint.txid}:{funding_outpoint.vout} "
        "SPENT but gave no well-formed spending txid, so the spend cannot be fetched or verified. "
        "This is NOT 'unspent': the counterparty may already have claimed and revealed p. Check the "
        "outpoint on another explorer or your own node now."
    )


async def read_btc_counter_leg(
    session: Any, base_url: str, *, funding_outpoint: BtcOutpoint, hashlock: bytes, timeout_s: float = 15.0
) -> CounterLegStatus:
    """Classify the BTC counter-leg through the SAME provenance-checked path as recovery."""
    spent, spender, raw = await fetch_btc_claim_bytes(session, base_url, funding_outpoint, timeout_s=timeout_s)
    source = endpoint_source_label(base_url)
    if not spent:
        return CounterLegStatus(
            chain="btc",
            state="LOCKED",
            source=source,
            reason=(
                f"{source} reports the BTC funding outpoint {funding_outpoint.txid}:{funding_outpoint.vout} "
                "UNSPENT — the counterparty has not claimed, so no preimage has been revealed. That is one "
                "server's answer, not a verified fact."
            ),
        )
    if spender is None:
        return CounterLegStatus(
            chain="btc", state="ERROR", reason=spent_spender_unknown_reason(source, funding_outpoint), source=source
        )
    if not raw:
        return CounterLegStatus(
            chain="btc",
            state="ERROR",
            reason=f"outpoint is spent by {spender} but its raw bytes are not retrievable yet (unindexed?)",
            claim_txid=spender,
            source=source,
        )
    try:
        rec = recover_preimage_from_btc_claim(
            raw, hashlock=hashlock, funding_outpoint=funding_outpoint, reported_txid=spender
        )
    except PreimageNotRevealed as exc:
        return CounterLegStatus(
            chain="btc", state="SPENT_NO_PREIMAGE", reason=str(exc), claim_txid=spender, source=source
        )
    except ProvenanceRefused as exc:
        return CounterLegStatus(chain="btc", state="ERROR", reason=str(exc), claim_txid=spender, source=source)
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
        source=source,
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


def _parse_chain_id(result: Any) -> int:
    """An ``eth_chainId`` result (a hex QUANTITY) as an int; ``ValidationError`` for anything else."""
    if isinstance(result, str) and re.fullmatch(r"0x(0|[1-9a-fA-F][0-9a-fA-F]{0,15})", result):
        return int(result, 16)
    raise ValidationError(f"eth_chainId returned {str(result)[:40]!r}, not a chain id; the RPC's chain is unknown")


def eth_chain_note(expected_chain_id: int | None) -> str:
    """One sentence saying what was checked about the RPC's chain — for status reasons and provenance."""
    if expected_chain_id is None:
        return (
            "the recovery file records no eth_chain_id, so the RPC's chain was NOT checked against the swap's "
            "(it was checked against the chain its own transaction bytes name, where there were any)"
        )
    return f"the RPC reports chain id {expected_chain_id}, the chain this swap's recovery file records"


async def check_eth_chain(session: Any, rpc_url: str, expected_chain_id: int | None, *, timeout_s: float = 15.0) -> int:
    """Ask the RPC which chain it is on (``eth_chainId``); refuse it unless it is the swap's.

    Returns the RPC's chain id. With ``expected_chain_id=None`` (a recovery file that records none)
    nothing is compared here, and the caller says so (:func:`eth_chain_note`).

    Raises
    ------
    WrongEthChain
        The RPC is on another chain than the one the swap's recovery file records.
    """
    actual = _parse_chain_id(await eth_rpc_read(session, rpc_url, "eth_chainId", [], timeout_s=timeout_s))
    if expected_chain_id is not None and actual != expected_chain_id:
        raise WrongEthChain(
            f"the RPC {endpoint_source_label(rpc_url)} is on chain {actual}, the swap is on chain {expected_chain_id} "
            "(eth_chain_id in the recovery file). Nothing it reports about the contract applies to this swap; "
            "use an RPC for the swap's chain."
        )
    return actual


async def fetch_eth_claim_artifacts(
    session: Any,
    rpc_url: str,
    *,
    contract_address: str,
    expected_chain_id: int | None,
    from_block: int | str = "0x0",
    timeout_s: float = 15.0,
) -> tuple[dict[str, Any] | VerifiedEthTx | None, list[dict[str, Any]]]:
    """Read ``(claim_tx, logs)`` for a per-swap HTLC contract. Read-only RPC only.

    FIRST asks the RPC for its chain (:func:`check_eth_chain`) and refuses one on another chain
    than ``expected_chain_id`` — the swap's, from its recovery file. Keyword-required with no
    default, so no caller can skip the decision; ``None`` means the file records no chain id. This
    is the one fetch both ``swap status`` and ``recover-preimage`` make, so the check covers both.
    A raw transaction whose own bytes name another chain than the RPC's is refused too.

    Scans every log from the contract (selector-agnostic, mirroring
    :class:`~pyrxd.gravity.watch.eth_adapters.RpcEthChainSource`) so a differently
    shaped claim event is never silently missed, then fetches the transaction that
    emitted the LAST one: first as raw signed bytes (``eth_getRawTransactionByHash``),
    hashed and decoded locally into a :class:`VerifiedEthTx`; if the RPC does not serve
    raw transactions, as ``eth_getTransactionByHash`` JSON (enough for a claim, whose
    ``p`` verifies itself). Neither form makes a refund definitive: a refund from one RPC is
    always :class:`RefundReportedUnconfirmed`.

    Raises
    ------
    WrongEthChain
        The RPC is on another chain than the swap's.
    ProvenanceRefused
        The raw bytes the RPC returned do not hash to the requested transaction, or name another
        chain than the RPC's.
    """
    rpc_chain = await check_eth_chain(session, rpc_url, expected_chain_id, timeout_s=timeout_s)
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
    # The last log emitted BY the contract — never a foreign log the RPC slipped into the answer.
    tx_hash = _fetched_tx_hash(logs, contract_address)
    if tx_hash is None:
        return None, logs
    import aiohttp

    try:
        raw = await eth_rpc_read(session, rpc_url, "eth_getRawTransactionByHash", [tx_hash], timeout_s=timeout_s)
    except (ValidationError, aiohttp.ClientResponseError):
        raw = None  # the method is not served (a JSON-RPC error, or a provider's 4xx): fall back to JSON
    if isinstance(raw, str) and _hex_blob(raw):
        verified = verify_raw_eth_tx(raw, tx_hash)
        if verified.chain_id is not None and verified.chain_id != rpc_chain:
            raise ProvenanceRefused(
                f"the transaction {verified.hash} the RPC returned is signed for chain {verified.chain_id}, but the "
                f"RPC reports chain {rpc_chain} — its answer contradicts itself; refusing to read it"
            )
        return verified, logs
    tx = await eth_rpc_read(session, rpc_url, "eth_getTransactionByHash", [tx_hash], timeout_s=timeout_s)
    return (tx if isinstance(tx, dict) else None), logs


async def read_eth_counter_leg(
    session: Any,
    rpc_url: str,
    *,
    contract_address: str,
    hashlock: bytes,
    expected_chain_id: int | None,
    timeout_s: float = 15.0,
) -> CounterLegStatus:
    """Classify the ETH counter-leg through the SAME decision as recovery.

    There is no ``LOCKED`` verdict on this chain: a log can show that the contract was claimed or
    refunded, never that it was not, and "no logs" is also what a pruned node or a log-range limit
    returns for a CLAIMED contract. That is reported ``UNKNOWN``, never ``LOCKED``. An RPC on
    another chain than ``expected_chain_id`` is ``ERROR`` (:class:`WrongEthChain`).
    """
    source = endpoint_source_label(rpc_url)
    try:
        tx, logs = await fetch_eth_claim_artifacts(
            session,
            rpc_url,
            contract_address=contract_address,
            expected_chain_id=expected_chain_id,
            timeout_s=timeout_s,
        )
    except (ProvenanceRefused, WrongEthChain) as exc:
        return CounterLegStatus(chain="eth", state="ERROR", reason=str(exc), source=source)
    status = _classify_eth_artifacts(tx, logs, contract_address=contract_address, hashlock=hashlock, source=source)
    if expected_chain_id is None:
        return replace(status, reason=f"{status.reason} (Note: {eth_chain_note(None)}.)")
    return status


def _classify_eth_artifacts(
    tx: dict[str, Any] | VerifiedEthTx | None,
    logs: list[dict[str, Any]],
    *,
    contract_address: str,
    hashlock: bytes,
    source: str,
) -> CounterLegStatus:
    """The :class:`CounterLegStatus` for ``(tx, logs)`` already read from one RPC."""
    if isinstance(tx, VerifiedEthTx):
        tx_hash: str | None = tx.hash
    else:
        tx_hash = tx.get("hash") if tx is not None and isinstance(tx.get("hash"), str) else None
    try:
        rec = recover_preimage_from_eth_artifacts(
            hashlock=hashlock, contract_address=contract_address, claim_tx=tx, logs=logs, source=source
        )
    except RefundReportedUnconfirmed as exc:
        # Not SPENT_NO_PREIMAGE: that state is "resolved" for swap status's situation table.
        return CounterLegStatus(
            chain="eth", state="REFUND_REPORTED_UNCONFIRMED", reason=str(exc), claim_txid=tx_hash, source=source
        )
    except CounterLegInconclusive as exc:
        return CounterLegStatus(chain="eth", state="UNKNOWN", reason=str(exc), claim_txid=tx_hash, source=source)
    except ProvenanceRefused as exc:
        return CounterLegStatus(chain="eth", state="ERROR", reason=str(exc), claim_txid=tx_hash, source=source)
    return CounterLegStatus(
        chain="eth",
        state="CLAIMED_PREIMAGE_REVEALED",
        reason=(
            f"the counterparty CLAIMED in {rec.claim_txid or 'a transaction the RPC did not name'} and the "
            "preimage p is now PUBLIC on ETH. Extract it with `pyrxd swap recover-preimage`, then "
            "`pyrxd swap build-claim` while the covenant's CSV refund window is still shut."
        ),
        claim_txid=rec.claim_txid,
        preimage_available=True,
        source=source,
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
            session,
            eth_rpc_url,
            contract_address=contract,
            hashlock=hashlock,
            expected_chain_id=facts.eth_chain_id,
            timeout_s=timeout_s,
        )


# --------------------------------------------------------------------------- Radiant reads


def electrumx_script_hash(spk: bytes | str) -> str:
    """ElectrumX ``script_hash`` for a raw scriptPubKey: ``sha256(spk)`` reversed."""
    raw = bytes.fromhex(spk) if isinstance(spk, str) else bytes(spk)
    return hashlib.sha256(raw).digest()[::-1].hex()


#: The covenant's history is read in full to find its spend; a covenant SPK is per swap, so its
#: history is the funding transaction and the one spend. Past this many entries something else
#: is paying the script, and the read reports UNKNOWN rather than fetch an unbounded list.
MAX_COVENANT_HISTORY = 16


@dataclass(frozen=True)
class CovenantSpend:
    """Which covenant branch spent the RXD covenant, read from the spending transaction itself.

    ``kind`` is ``TAKER_CLAIM`` (function 0: ``<p> OP_0``, the covenant then pays the taker),
    ``MAKER_REFUND`` (function 1: ``OP_1`` after the CSV, the covenant then pays the maker), or
    ``UNKNOWN`` with the reason. A spent covenant looks the same either way from its UTXO set,
    which is why ``swap status`` used to call a maker's refund + the maker's counter-leg claim
    SETTLED. ``p`` itself is never carried here.
    """

    kind: str
    reason: str
    spend_txid: str | None = None
    height: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "reason": self.reason, "spend_txid": self.spend_txid, "height": self.height}


def _push_values(unlocking: bytes) -> list[bytes] | None:
    """The stack a push-only scriptSig leaves, or ``None`` if it is not push-only / unparseable."""
    try:
        chunks = Script(bytes(unlocking)).chunks
    except Exception:
        return None
    out: list[bytes] = []
    for ch in chunks:
        op = ch.op[0]
        if op == 0x00:
            out.append(b"")
        elif op == 0x4F:  # OP_1NEGATE
            out.append(b"\x81")
        elif 0x51 <= op <= 0x60:  # OP_1 .. OP_16
            out.append(bytes([op - 0x50]))
        elif ch.data is not None and op <= 0x4E:
            out.append(bytes(ch.data))
        else:
            return None
    return out


def _script_num(b: bytes) -> int:
    """Decode a stack item as a script number (little-endian sign-magnitude; empty is 0)."""
    if not b:
        return 0
    mag = int.from_bytes(b[:-1] + bytes([b[-1] & 0x7F]), "little")
    return -mag if b[-1] & 0x80 else mag


def classify_covenant_spend_input(unlocking: bytes, *, hashlock: bytes | None) -> str | None:
    """``"claim"`` / ``"refund"`` for a covenant input's scriptSig, or ``None`` if neither.

    The covenant dispatches on the TOP stack item (``OP_DUP OP_0 OP_NUMEQUAL OP_IF <claim> OP_ELSE
    OP_1 OP_NUMEQUALVERIFY <refund>``; see :mod:`pyrxd.gravity.htlc_spend`), so the branch a mined
    spend took is that item's numeric value — ``build_htlc_claim_tx`` pushes ``<p> OP_0`` and
    ``build_htlc_refund_tx`` pushes ``OP_1``. Decoded numerically rather than by byte pattern, so a
    non-minimal encoding the interpreter accepts is classified the same. A claim must also carry a
    value hashing to ``hashlock`` (the claim branch cannot validate without one).
    """
    items = _push_values(unlocking)
    if not items:
        return None
    selector = _script_num(items[-1]) if len(items[-1]) <= 4 else None
    if selector == 1:
        return "refund"
    if selector == 0 and hashlock is not None:
        h = bytes(hashlock)
        if any(len(v) == 32 and hashlib.sha256(v).digest() == h for v in items[:-1]):
            return "claim"
    return None


async def read_covenant_spend(
    client: Any, spk_hex: str, history: Sequence[dict[str, Any]], *, hashlock: bytes | None
) -> CovenantSpend:
    """Find the transaction that spent the covenant and say which branch it took. Read-only.

    Fetches each transaction in the covenant script's history (``get_transaction``), re-derives
    its txid from the bytes (a server serving the wrong transaction is not believed), finds the
    covenant output(s) the funding transaction created, and classifies the input that spends one.
    Anything it cannot establish is ``UNKNOWN`` with the reason — never a guess.
    """
    spk = bytes.fromhex(spk_hex)
    entries = [e for e in history if isinstance(e, dict) and isinstance(e.get("tx_hash"), str)]
    if not entries:
        return CovenantSpend("UNKNOWN", "the covenant script's history is empty, so no spend could be read")
    if len(entries) > MAX_COVENANT_HISTORY:
        return CovenantSpend(
            "UNKNOWN",
            f"the covenant script has {len(entries)} history entries (more than {MAX_COVENANT_HISTORY}); "
            "something other than this swap is paying it, so its spend was not read",
        )
    txs: dict[str, tuple[Transaction, int | None]] = {}
    for e in entries:
        txid = e["tx_hash"]
        raw = await client.get_transaction(txid)
        tx = Transaction.from_hex(bytes(raw)) if isinstance(raw, (bytes, bytearray)) else None
        if tx is None or tx.txid() != txid:
            return CovenantSpend(
                "UNKNOWN", f"the server's bytes for covenant history transaction {txid} do not parse to that txid"
            )
        height = e.get("height")
        txs[txid] = (tx, height if isinstance(height, int) and height > 0 else None)
    funded = {
        (txid, i)
        for txid, (tx, _) in txs.items()
        for i, out in enumerate(tx.outputs)
        if out.locking_script is not None and out.locking_script.serialize() == spk
    }
    kinds: set[str] = set()
    spender: tuple[str, int | None] | None = None
    for txid, (tx, height) in txs.items():
        for inp in tx.inputs:
            if (inp.source_txid, inp.source_output_index) not in funded:
                continue
            unlocking = inp.unlocking_script.serialize() if inp.unlocking_script is not None else b""
            kind = classify_covenant_spend_input(unlocking, hashlock=hashlock)
            if kind is None:
                return CovenantSpend(
                    "UNKNOWN",
                    f"transaction {txid} spends the covenant with an unlocking script that is neither the "
                    "claim branch nor the refund branch",
                    spend_txid=txid,
                    height=height,
                )
            kinds.add(kind)
            spender = (txid, height)
    if spender is None:
        return CovenantSpend(
            "UNKNOWN",
            "no transaction in the covenant script's history spends the covenant output — the server's "
            "history is incomplete, so who spent it is not known",
        )
    if len(kinds) > 1:
        return CovenantSpend("UNKNOWN", "the covenant was spent through BOTH branches (more than one funding)")
    txid, height = spender
    when = f"at height {height}" if height is not None else "UNCONFIRMED"
    if kinds == {"claim"}:
        return CovenantSpend(
            "TAKER_CLAIM",
            f"the taker CLAIMED the covenant in {txid} ({when}); the covenant pays the claim to the taker",
            spend_txid=txid,
            height=height,
        )
    return CovenantSpend(
        "MAKER_REFUND",
        f"the maker CSV-REFUNDED the covenant in {txid} ({when}); the covenant pays the refund to the maker",
        spend_txid=txid,
        height=height,
    )


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
    broadcast.

    ``depth_unresolved``
    --------------------
    The one triple that is *not* self-contradictory but also not a depth is
    ``funding_height > tip_height`` reached honestly. ``read_covenant_chain_state``
    makes TWO round trips — ``listunspent`` then ``get_tip_height`` — and failover is
    per call, so the tip can come from a different, lagging endpoint than the one that
    answered ``listunspent``, and a reorg can land between them. That is not a lying
    server; it is two reads of a moving chain.

    Refusing to construct at all was wrong for that case: it fired inside the
    constructor, before ``--allow-unconfirmed`` could be consulted, on the COLD-RECOVERY
    path, during a CSV race, on a chain with no second chance. So the reader
    re-reads the tip first (see :func:`read_covenant_chain_state`), and only if the
    views still disagree records ``depth_unresolved=True``, keeping BOTH real numbers
    rather than inventing a third. Nothing downstream then reads a depth it did not
    measure: :func:`_assert_covenant_confirmed` refuses (overridably, same escape hatch),
    :func:`build_cold_refund` refuses because CSV maturity cannot be shown, and
    :func:`build_cold_claim` takes ``blocks_to_deadline = 0`` — MAXIMUM urgency, the
    conservative direction, never the optimistic one this class exists to prevent.
    """

    outpoint: str  # "txid:vout"
    carrier_value: int
    funding_height: int | None
    tip_height: int
    confirmations: int
    #: Set only by :func:`read_covenant_chain_state` when a re-read could not reconcile
    #: a funding height above the tip. Never a value an operator should pass by hand.
    depth_unresolved: bool = False

    def __post_init__(self) -> None:
        if self.tip_height < 0:
            raise ValidationError(f"tip_height must be >= 0, got {self.tip_height}")
        if self.depth_unresolved:
            # The ONLY shape this flag describes: a real funding height, a real tip
            # below it, and no depth claimed from the pair.
            if self.funding_height is None or self.funding_height <= self.tip_height:
                raise ValidationError(
                    "depth_unresolved is only for a funding height that a re-read still put ABOVE the "
                    f"tip; got funding_height={self.funding_height}, tip_height={self.tip_height}."
                )
            if self.confirmations != 0:
                raise ValidationError(
                    f"depth_unresolved claims {self.confirmations} confirmations. An unresolved depth is "
                    "not a measured one — it must be 0."
                )
            return
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
                "CSV deadline. (Reached through a lagging endpoint or a reorg between two reads, this "
                "is what read_covenant_chain_state's tip re-read and depth_unresolved are for.)"
            )
        expected = self.tip_height - self.funding_height + 1
        if self.confirmations != expected:
            raise ValidationError(
                f"confirmations {self.confirmations} does not match tip {self.tip_height} minus funding "
                f"height {self.funding_height} plus one ({expected})."
            )


async def read_covenant_chain_state(
    client: Any, spk_hex: str, *, tip_reread_attempts: int = _TIP_REREAD_ATTEMPTS
) -> CovenantChainState:
    """Locate the live covenant UTXO for ``spk_hex`` and measure its depth.

    Refuses ambiguity rather than guessing: a covenant SPK that holds more than one
    UTXO cannot be resolved to "the" covenant outpoint, and picking one silently could
    build a spend of the wrong output.

    **Two round trips, one moving chain.** ``listunspent`` and ``get_tip_height`` are
    separate calls, and :class:`~pyrxd.network.failover.FailoverElectrumXClient` picks
    an endpoint *per call* — so the tip can arrive from a different, lagging server than
    the one that reported the UTXO, and a reorg can land between the two. Either
    produces ``funding_height > tip_height``, which :class:`CovenantChainState` refuses.
    That refusal is right about a single consistent view and wrong about this one, and
    it fired in a constructor, ahead of ``--allow-unconfirmed``, on the cold-recovery
    path. So the tip is re-read up to ``tip_reread_attempts`` times (the highest reading
    wins — a tip only moves forward) before any conclusion is drawn. Only if the views
    still disagree is ``depth_unresolved`` set, which every consumer treats
    conservatively; see :class:`CovenantChainState`.
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
    if height is not None and height > tip:
        for _ in range(max(0, tip_reread_attempts)):
            tip = max(tip, int(await client.get_tip_height()))
            if height <= tip:
                break
    if height is not None and height > tip:
        logger.warning(
            "covenant %s:%s reports funding height %d but the best tip read across %d attempt(s) is %d. "
            "Two reads of a moving chain (per-call failover, or a reorg between them) disagree, so the "
            "confirmation depth is UNKNOWN — not zero. Treating it as unresolved: this run will assume "
            "the deadline is imminent rather than assume time it has not measured. Re-run against a "
            "single, caught-up endpoint to get a real depth.",
            u.tx_hash,
            u.tx_pos,
            height,
            max(0, tip_reread_attempts),
            tip,
        )
        return CovenantChainState(
            outpoint=f"{u.tx_hash}:{u.tx_pos}",
            carrier_value=int(u.value),
            funding_height=height,
            tip_height=tip,
            confirmations=0,
            depth_unresolved=True,
        )
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


# The overpay bound (`MAX_FEE_OVERPAY_MULTIPLE`, `fee_overpay_ceiling`,
# `fee_overpay_multiple`) is defined ONCE, in `pyrxd.fee_sizing`, and imported at the
# top of this module. It started life here, but a rule only the CLI could reach is a
# rule the BUILDERS could not: `gravity.htlc_spend` has the same
# single-output/whole-input-is-the-fee shape and cannot import a `pyrxd.cli` module to
# find the number. It now warns on the same ceiling this path refuses on — see
# `MAX_FEE_OVERPAY_MULTIPLE`'s own note for why those two responses differ.
#
# `fee_overpay_ceiling` is what the cold path will burn without an explicit
# `--allow-overpay`.


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
    :func:`~pyrxd.fee_sizing.fee_overpay_ceiling` the input is refused as an overpay
    (audit B4) — :func:`pyrxd.gravity.htlc_spend._check_carrier`'s dust check claimed to
    guard "a mistakenly-huge UTXO" and only ever checked the small end.
    ``allow_overpay=True`` is the deliberate override, and it applies to an explicitly
    named ``--fee-utxo`` too: naming a UTXO by hand is not consent to burn 500 RXD on a
    0.0266 RXD fee.

    The builders now bound the same end on the same ceiling, but they WARN where this
    REFUSES (:func:`pyrxd.gravity.htlc_spend._warn_if_fee_is_an_overpay`). Deliberate: here
    an operator is present and ``--allow-overpay`` is one flag away, while an autonomous
    claim executor racing a CSV refund would lose the asset outright if the build failed.
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
    #: True when ``csv_confirmations`` is 0 because the depth could not be MEASURED, not
    #: because the covenant is 0-conf. Without it the payload would report "0 confirmations"
    #: for a covenant that is almost certainly mined — a number nothing established.
    depth_unresolved: bool = False

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
            "depth_unresolved": self.depth_unresolved,
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

    An UNRESOLVED depth (``depth_unresolved``) is refused by the same gate but for a
    different reason and with a different message: the funding is almost certainly mined,
    but two reads of the chain disagreed about how deep, so no depth was measured. The
    ``--allow-unconfirmed`` override covers both — it is the operator saying "I know what
    I am building on" — and this used to be reachable only because the pre-guard code
    silently reported such a state as 0 confirmations.
    """
    if chain.confirmations >= 1 or allow_unconfirmed:
        return
    if chain.depth_unresolved:
        raise ValidationError(
            f"the covenant's confirmation depth could not be established — refusing to build a cold "
            f"{kind}. The UTXO reports funding height {chain.funding_height} while the best chain tip "
            f"read was {chain.tip_height}: two reads of a moving chain disagree (a lagging endpoint, or "
            "a reorg between them). Depth drives the CSV deadline arithmetic, and guessing it low would "
            "report MORE time than you have. Re-run against a single, caught-up endpoint, or pass "
            "--allow-unconfirmed to build anyway — the fee will then be sized as if the deadline were "
            "imminent."
        )
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

    Refuses a 0-conf (mempool-only) covenant, and a covenant whose depth two chain reads
    could not agree on, unless ``allow_unconfirmed`` — see
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
    # An unresolved depth is not a depth of zero. ``chain.confirmations`` is 0 there only
    # because there is nothing honest to put in it, and feeding that 0 into the
    # subtraction below would report the FULL CSV window as remaining — the optimistic
    # direction, on the path where being late is unrecoverable. Take 0 blocks to the
    # deadline instead: maximum urgency premium, which costs fee and never time.
    blocks_to_deadline = 0 if chain.depth_unresolved else max(0, covenant.refund_csv - chain.confirmations)
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
        csv_mature=not chain.depth_unresolved and chain.confirmations >= covenant.refund_csv,
        depth_unresolved=chain.depth_unresolved,
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
    covenant is still refused unless ``allow_unconfirmed`` is also passed. A covenant whose
    depth is UNRESOLVED reads as immature here, which is the fail-closed direction — CSV
    maturity is the one thing an unmeasured depth cannot be used to claim.
    """
    pol = policy or DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    _assert_covenant_confirmed(chain, allow_unconfirmed=allow_unconfirmed, kind="refund")
    mature = not chain.depth_unresolved and chain.confirmations >= covenant.refund_csv
    if not mature and not allow_immature:
        if chain.depth_unresolved:
            raise ValidationError(
                f"the covenant's CSV maturity cannot be shown: it needs {covenant.refund_csv} "
                f"confirmations and its depth is UNRESOLVED (funding height {chain.funding_height} vs "
                f"best tip read {chain.tip_height} — two reads of a moving chain disagree). Re-run "
                "against a single, caught-up endpoint, or pass --allow-immature to pre-build it anyway "
                "(build now, broadcast at maturity) — but do NOT broadcast it before then."
            )
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
        depth_unresolved=chain.depth_unresolved,
        outputs=_decode_outputs(tx, covenant, "refund"),
        overpay_multiple=fee_overpay_multiple(fee.value, floor=floor, target=target),
        is_overpay=fee.value > fee_overpay_ceiling(floor=floor, target=target),
    )
