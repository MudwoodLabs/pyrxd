"""Read-only ``pyrxd swap`` CLI — inspect a Gravity cross-chain swap from its recovery file.

``swap status --swap-file PATH`` parses the recovery JSON the swap harnesses write (BTC↔RXD or
ETH↔RXD) and prints the swap's identity + timelock deadlines. With ``--check-chain`` it additionally
does a **read-only** ElectrumX query of the RXD covenant to classify the live situation and the single
safe next action. **It never broadcasts** — so it sidesteps the swap audit gate entirely.

``--check-chain`` also reads the **counter-leg** (BTC or ETH) through the provenance-checked path in
:mod:`pyrxd.cli.swap_recovery`, so it can say whether the counterparty's claim has revealed the
preimage ``p``. That is the difference between "keep waiting" and "claim NOW" and the RXD covenant
alone cannot show it: a live covenant looks identical either way. The counter-leg read needs a
locator + an endpoint that the recovery file may not carry, so when either is missing it reports
``NOT_CHECKED`` *with the reason* rather than failing — the covenant verdict is still worth having.

The recovery file holds WIFs + the preimage; this command reads them only to derive public facts and
**never echoes any secret** — output carries booleans (``has_preimage``/``has_keys``) and a hygiene
reminder, not key material. The counter-leg verdict likewise reports only that a preimage IS
recoverable; extracting it is ``pyrxd swap recover-preimage``.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

from ..security.errors import ValidationError
from .context import CliContext
from .format import emit, sanitize_terminal
from .swap_recovery import (
    CounterLegStatus,
    CovenantSpend,
    CovenantUnidentified,
    describe_network_error,
    electrumx_urls,
    locate_covenant_funding,
    parse_outpoint,
    parse_recovery_extras,
    read_counter_leg,
    read_covenant_spend,
    recorded_covenant_value,
)

#: Default Esplora/mempool.space base URL for the BTC counter-leg read (a GET-only API).
DEFAULT_BTC_API_URL = "https://mempool.space"

# --------------------------------------------------------------------------- recovery-file parsing


@dataclass(frozen=True)
class SwapFacts:
    """Public facts extracted from a swap recovery file — never carries a secret."""

    counter_chain: str  # "btc" | "eth"
    hashlock_hex: str
    asset_variant: str  # "rxd" | "ft" | "nft"
    rxd_covenant_spk: str
    rxd_network: str
    t_rxd_blocks: int
    stage: str | None = None
    has_preimage: bool = False
    has_keys: bool = False
    # BTC counter-leg
    t_btc_blocks: int | None = None
    btc_htlc_address: str | None = None
    btc_network: str | None = None
    # ETH counter-leg
    eth_chain: str | None = None
    #: The EVM chain id the swap's HTLC lives on (``eth_chain_id``, written by
    #: ``scripts/eth_swap_run.py``), or ``None`` when the file records none. The counter-leg read
    #: refuses an RPC on any other chain (:func:`~pyrxd.cli.swap_recovery.check_eth_chain`).
    eth_chain_id: int | None = None
    eth_timeout_unix_s: int | None = None
    eth_amount_wei: int | None = None
    # asset detail (ft/nft)
    asset_genesis_ref: str | None = None
    asset_ft_amount: int | None = None
    #: The in-tree harness that wrote the file (:func:`recovery_file_writer`), or ``None``
    #: when its fields match none of them.
    writer: str | None = None
    #: The recovery file names the taker's counter-leg refund key (``taker_btc_wif``).
    has_btc_refund_key: bool = False
    #: The ETH HTLC's immutable refundee, as the harness recorded it (``eth_refund_to``).
    eth_refund_to: str | None = None


#: The three harnesses whose recovery file this parser accepts, each told apart by a field
#: only that writer emits. Read from the writers, not assumed: ``scripts/dust_swap_run.py``
#: (``keys_payload``: ``taker_btc_wif``, ``btc_htlc_address``), ``scripts/eth_swap_run.py``
#: (``eth_chain_id``) and ``scripts/eth_swap_grief_run.py`` (``"scenario": "grief-S1"``).
#: The two-host harnesses write ``hashlock_H_hex`` and are refused before this is reached
#: (:func:`_two_host_refusal`).
_DUST_SWAP_RUN = "scripts/dust_swap_run.py"
_ETH_SWAP_RUN = "scripts/eth_swap_run.py"
_ETH_SWAP_GRIEF_RUN = "scripts/eth_swap_grief_run.py"


def recovery_file_writer(d: dict[str, Any]) -> str | None:
    """Which in-tree harness wrote this recovery document, or ``None`` if none matches."""
    if d.get("scenario") == "grief-S1":
        return _ETH_SWAP_GRIEF_RUN
    if "eth_chain_id" in d:
        return _ETH_SWAP_RUN
    if "taker_btc_wif" in d or "btc_htlc_address" in d:
        return _DUST_SWAP_RUN
    return None


def _in_tree_script(name: str) -> Path | None:
    """``scripts/<name>`` beside this package when pyrxd runs from a source checkout, else ``None``.

    ``scripts/`` ships in the sdist only (``pyproject.toml``), never in the wheel, so on a pip
    install this is ``None`` and no text may point at a path that is not there.
    """
    candidate = Path(__file__).resolve().parents[3] / "scripts" / name
    return candidate if candidate.is_file() else None


def _two_host_refusal(d: dict[str, Any], path: Path) -> str | None:
    """The refusal for a two-host harness's LOCAL secret file, naming that harness's own recovery.

    ``btc_swap_two_host.py`` / ``eth_swap_two_host.py`` keep each role's private state in a
    ``--local-out`` file that carries no ``hashlock_H`` or covenant SPK under the names this
    parser reads (the maker's has ``hashlock_H_hex``; the taker's has neither — both live in the
    exchange directory's ``envelope.json``). Refusing with "not a swap recovery file" left a
    taker holding the one file it has with no pointer to the phase that refunds its leg.
    """
    if d.get("role") not in ("maker", "taker"):
        return None
    if "taker_btc_refund_wif" in d or "maker_btc_claim_privkey_hex" in d:
        name, chain = "btc_swap_two_host.py", "BTC"
    elif "eth_taker_refund_addr" in d:
        name, chain = "eth_swap_two_host.py", "ETH"
    else:
        return None
    here = _in_tree_script(name)
    if here is not None:
        script, where = str(here), f"from the source tree at {here.parents[1]}"
    else:
        script = f"scripts/{name}"
        where = (
            f"from the source checkout you ran the swap from — scripts/{name} is not part of pyrxd "
            "as installed here (scripts/ ships only in the source distribution)"
        )
    role = d["role"]
    head = (
        f"this is the {role.upper()}'s local secret file from scripts/{name}, not a recovery file this "
        "toolkit reads: the hashlock and covenant SPK it needs live in that harness's envelope.json."
    )
    if role == "taker":
        return (
            f"{head} To get your own {chain} back once its timelock has passed, run that harness's "
            f"recovery phase {where}: `python {script} --role taker --phase abort --io DIR "
            f"--local-out {path}` with the same chain flags you passed to `--phase fund`. DIR is the "
            "exchange directory and must hold envelope.json and taker_funding.json."
        )
    return (
        f"{head} The maker's recovery phases are in that harness, run {where}: `python {script} "
        f"--role maker --phase abort --io DIR --local-out {path}` if the taker never funded (DIR holds "
        "envelope.json and no taker_funding.json), or `--phase refund` once both legs are locked (DIR "
        "holds taker_funding.json); both spend the covenant, so both need the --fee-* flags."
    )


def parse_recovery_file(path: Path) -> SwapFacts:
    """Parse a harness recovery JSON into public :class:`SwapFacts`.

    Reads through :func:`~pyrxd.cli.swap_recovery.load_recovery_json`, so the same file
    that gets ``has_keys=True`` reported about it is also refused if it holds those keys
    at a group/world-readable mode. Telling an operator their file contains private keys
    while reading it out of a 0644 file without comment was the wrong half of the job.

    ``has_keys`` is :func:`~pyrxd.cli.swap_recovery._carries_private_key` itself, not a
    second opinion about the same question. It used to be a private marker list here
    (``("wif", "key_hex", "secret", "preimage", "privkey")``) scanned over the TOP-LEVEL
    keys only, and the two answers measurably disagreed about the same document: a file
    carrying ``{"mnemonic": …}`` was reported ``has_keys=False`` at 0600 and refused as
    "contains a private key" at 0644. A tool that contradicts itself about whether a
    file holds keys teaches an operator to disbelieve both answers.

    The dropped ``"preimage"`` marker is not a lost signal: ``has_preimage`` reports it
    separately and ``holds_secrets`` (what the command actually prints) is still
    ``has_preimage or has_keys``. Dropping it from ``has_keys`` is deliberate — ``p`` is
    published on-chain by the claim that reveals it, so it is not spending authority and
    the mode gate rightly does not demand 0600 for it.

    Raises:
        ValueError: the document parses but does not look like a swap recovery file
            (missing the covenant SPK + hashlock, or a non-integer ``t_rxd_blocks``).
        ValidationError: raised by ``load_recovery_json`` before this function sees
            anything — the file is unreadable, oversized, not JSON, not an object, or
            holds a key at a group/world-readable mode. This docstring promised only
            ``ValueError`` after the read moved behind that gate; both in-repo callers
            already catch the wider type, so the promise was the thing that was wrong.
    """
    from .swap_recovery import _carries_private_key, load_recovery_json

    d = load_recovery_json(path)
    hashlock = d.get("hashlock_H")
    spk = d.get("rxd_covenant_spk")
    if not hashlock or not spk:
        two_host = _two_host_refusal(d, path)
        if two_host is not None:
            raise ValueError(two_host)
        raise ValueError("not a swap recovery file (missing hashlock_H / rxd_covenant_spk)")
    t_rxd = d.get("t_rxd_blocks")
    if not isinstance(t_rxd, int):
        raise ValueError("recovery file missing integer t_rxd_blocks")

    # ``eth_timeout_unix_s`` too: ``eth_swap_grief_run.py`` writes no ``eth_chain``, so its ETH
    # swap used to be classified BTC and its counter-leg read asked for a BTC outpoint.
    is_eth = ("eth_chain" in d) or ("eth_timeout_unix_s" in d) or (d.get("counter_chain") == "eth")
    eth_chain_id = d.get("eth_chain_id")
    if eth_chain_id is not None and (
        not isinstance(eth_chain_id, int) or isinstance(eth_chain_id, bool) or eth_chain_id <= 0
    ):
        # Refused, not ignored: a malformed value silently read as "none recorded" would switch the
        # counter-leg read's chain check off for exactly the file that tried to pin it.
        raise ValueError("recovery file eth_chain_id must be a positive integer")
    return SwapFacts(
        counter_chain="eth" if is_eth else "btc",
        hashlock_hex=str(hashlock),
        asset_variant=str(d.get("asset_variant", "rxd")),
        rxd_covenant_spk=str(spk),
        rxd_network=str(d.get("rxd_network", "bc")),
        t_rxd_blocks=t_rxd,
        stage=d.get("stage"),
        # Substring, not the exact ``preimage_p_hex`` this used to test for: the old
        # marker list made ANY ``*preimage*`` field count toward ``holds_secrets``, and
        # moving ``has_keys`` onto the gate's predicate would otherwise have narrowed
        # that. Same top-level-only scope as before.
        has_preimage=any(isinstance(k, str) and "preimage" in k.lower() for k in d),
        has_keys=_carries_private_key(d),
        t_btc_blocks=d.get("t_btc_blocks"),
        btc_htlc_address=d.get("btc_htlc_address"),
        btc_network=d.get("btc_network"),
        eth_chain=d.get("eth_chain"),
        eth_chain_id=eth_chain_id,
        eth_timeout_unix_s=d.get("eth_timeout_unix_s"),
        eth_amount_wei=d.get("eth_amount_wei"),
        asset_genesis_ref=d.get("asset_genesis_ref"),
        asset_ft_amount=d.get("asset_ft_amount"),
        writer=recovery_file_writer(d),
        has_btc_refund_key=bool(d.get("taker_btc_wif")),
        eth_refund_to=d.get("eth_refund_to") if isinstance(d.get("eth_refund_to"), str) else None,
    )


# --------------------------------------------------------------------------- covenant classification


def electrumx_script_hash(spk_hex: str) -> str:
    """ElectrumX ``script_hash`` for a raw scriptPubKey: ``sha256(spk)`` reversed (display order)."""
    return hashlib.sha256(bytes.fromhex(spk_hex)).digest()[::-1].hex()


#: Counter-leg states in which that leg is finished: claimed by the maker (revealing p) or
#: spent without revealing p (the taker's refund; BTC only — an ETH refund read from one RPC is
#: REFUND_REPORTED_UNCONFIRMED, deliberately absent here). Only these, together with a spent
#: covenant, justify "no further action".
_COUNTER_LEG_RESOLVED = frozenset({"CLAIMED_PREIMAGE_REVEALED", "SPENT_NO_PREIMAGE"})


def counter_leg_refund_advice(facts: SwapFacts, *, now_unix_s: int | None = None) -> str:
    """What the TAKER can actually do to refund its own counter-leg, for this recovery file.

    This used to name ``scripts/*_swap_two_host.py --role taker --phase abort`` for every file.
    That command could not run from here: it needs the two-host exchange directory
    (``envelope.json``, ``taker_funding.json``) and that harness's own local secret file, and this
    parser accepts only the files the OTHER three harnesses write — none of which has a phase that
    refunds only the counter-leg. ``scripts/`` is also absent from a pip install. So the advice is
    the plain truth instead: no pyrxd command can do it from this file, the leg stays locked until refunded,
    when its refund opens, and what in THIS file the refund needs.
    """
    chain = facts.counter_chain.upper()
    if facts.writer is not None:
        who = f"{facts.writer}, which wrote this file, has no phase that refunds only that leg"
    else:
        who = "this file matches none of the in-tree harnesses, so pyrxd cannot name the tool that wrote it"
    if facts.counter_chain == "btc":
        t_btc = facts.t_btc_blocks
        if isinstance(t_btc, int) and not isinstance(t_btc, bool):
            when = (
                f"its refund branch opens {t_btc} BTC blocks after the HTLC funding confirmed "
                "(a relative CSV timelock; t_btc_blocks in this file)"
            )
        else:
            when = "its refund branch opens at the HTLC's own CSV timelock (t_btc), which this file does not record"
        how = (
            "Spend the HTLC's refund branch with a tool that can; this file holds the refund key as `taker_btc_wif`."
            if facts.has_btc_refund_key
            else "Refund it with the tool that funded it."
        )
    else:
        ts = facts.eth_timeout_unix_s
        if isinstance(ts, int) and not isinstance(ts, bool):
            now = int(time.time()) if now_unix_s is None else now_unix_s
            iso = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            passed = (
                "already passed by this machine's clock; the contract checks block time"
                if now >= ts
                else "still ahead by this machine's clock"
            )
            when = f"the HTLC contract's refund() opens at unix time {ts} ({iso}; {passed})"
        else:
            when = "the HTLC contract's refund() opens at its own timeout, which this file does not record"
        how = (
            "Refund it by calling refund() on the HTLC contract, which pyrxd cannot send; the contract pays "
            f"the refundee fixed at deploy (`eth_refund_to` = {sanitize_terminal(facts.eth_refund_to, max_len=64)})."
            if facts.eth_refund_to
            else "Refund it with the tool that funded it."
        )
    return (
        f"No pyrxd command can refund the {chain} leg from this file, and {who}. Your {chain}-side funds "
        f"stay locked until refunded; {when}. {how}"
    )


def _covenant_spent(
    counter_chain: str,
    counter_leg_state: str | None,
    *,
    refund_advice: str | None = None,
    counter_leg_source: str | None = None,
    spend_kind: str | None = None,
) -> tuple[str, str]:
    """A spent covenant says nothing on its own about whether the swap is over.

    The covenant is spent both by the taker's claim and by the maker's CSV refund, and the two
    look identical from its UTXO set. ``spend_kind`` (:class:`~pyrxd.cli.swap_recovery.CovenantSpend`)
    is which one it was, read from the spending transaction; ``None``/``"UNKNOWN"`` when that
    transaction could not be read. Together with the counter-leg that decides the outcome:

    ================  ===========================  ===============================
    covenant spend    counter-leg                  situation
    ================  ===========================  ===============================
    TAKER_CLAIM       claimed with p               SETTLED (swap completed)
    MAKER_REFUND      spent, no p (refunded)       SETTLED (aborted, both refunded)
    MAKER_REFUND      claimed with p               MAKER_REFUNDED_AND_CLAIMED
    TAKER_CLAIM       spent, no p (refunded)       TAKER_CLAIMED_AND_REFUNDED
    UNKNOWN           spent either way             BOTH_SPENT_OUTCOME_UNKNOWN
    any               LOCKED                       COUNTER_LEG_LOCKED
    any               BTC refund, unconfirmed      COUNTER_LEG_REFUND_UNCONFIRMED
    any               anything else                COVENANT_SPENT
    ================  ===========================  ===============================

    SETTLED used to be printed for every "both legs spent", so a maker who CSV-refunded the
    covenant AND claimed the counter-leg — the taker losing both legs — read "nothing left to
    claim or refund" directly above the counter-leg row that contradicted it.

    Every row rests on one ElectrumX server's answer and one counter-chain server's, and the text
    says so. None of them says outright that nothing is left to claim or refund: a refund the
    explorer reports but has not confirmed can still be replaced by a claim (the BTC claim branch
    has no timelock), and a covenant spend one ElectrumX reports may not exist on any other.
    """
    chain = counter_chain.upper()
    kind = spend_kind if spend_kind in ("TAKER_CLAIM", "MAKER_REFUND") else None
    if refund_advice is None:
        refund_advice = (
            f"No pyrxd command can refund the {chain} leg from this file; refund it with the tool that funded it, "
            "once that leg's own timelock has passed."
        )
    no_timelock = (
        " The BTC claim branch has NO timelock: a maker who refunded the covenant can still sweep "
        "your BTC with p until you refund it."
        if counter_chain == "btc"
        else ""
    )
    # The host came from the operator's own URL, but the line it lands on is printed raw.
    source = sanitize_terminal(counter_leg_source, max_len=120) if counter_leg_source else "one server"
    rxd_hedge = "The covenant's spend is one ElectrumX server's answer, too."
    second = (
        "Confirm both spends on a second, independent source (another ElectrumX server and another "
        f"{chain} explorer or node) before treating the swap as finished."
    )
    if counter_leg_state in _COUNTER_LEG_RESOLVED:
        claimed = counter_leg_state == "CLAIMED_PREIMAGE_REVEALED"
        how_spent = "claimed with p" if claimed else "spent by a transaction that reveals no preimage (a refund)"
        hedge = f"{source} reports the {chain} leg {how_spent} — that is one server's answer, not a verified fact."
        if kind == "MAKER_REFUND" and claimed:
            return (
                "MAKER_REFUNDED_AND_CLAIMED",
                f"The MAKER took BOTH legs: they CSV-refunded the RXD covenant AND claimed the {chain} leg. "
                f"{hedge} {rxd_hedge} TAKER: if a second, independent source confirms both spends, you received "
                f"neither the asset nor your {chain} back. If the covenant is still unspent on another ElectrumX "
                "server, claim it with p now. Read both spending transactions before acting on this.",
            )
        if kind == "TAKER_CLAIM" and not claimed:
            return (
                "TAKER_CLAIMED_AND_REFUNDED",
                f"The TAKER took BOTH legs: they claimed the RXD covenant with p AND the {chain} leg was "
                f"spent without revealing p. {hedge} {rxd_hedge} MAKER: if a second, independent source confirms "
                f"both spends, you received neither the {chain} nor the asset back. Read both spending "
                "transactions before acting on this.",
            )
        if kind is None:
            return (
                "BOTH_SPENT_OUTCOME_UNKNOWN",
                f"Both legs are reported spent, but the RXD covenant's spending transaction could not be read, so "
                f"whether the taker claimed it or the maker refunded it is UNKNOWN — this is NOT a confirmed "
                f"settlement. {hedge} The covenant's state is one ElectrumX server's answer. Read the covenant "
                "on a second, independent ElectrumX server: if it is still unspent there and you are the TAKER "
                "holding p, claim it now; otherwise its spending transaction shows who received the asset.",
            )
        outcome = (
            f"The swap COMPLETED: the taker claimed the RXD covenant and the maker claimed the {chain} leg with p."
            if kind == "TAKER_CLAIM"
            else f"The swap was ABORTED and both sides refunded: the maker CSV-refunded the RXD covenant and the "
            f"taker refunded the {chain} leg."
        )
        return (
            "SETTLED",
            f"{outcome} {hedge} {rxd_hedge} {second} No further action once a second, independent source "
            "confirms both spends.",
        )
    if counter_leg_state == "REFUND_REPORTED_UNCONFIRMED" and counter_chain == "btc":
        # A BTC refund still in the mempool is not a finished leg: the HTLC's claim branch has no
        # timelock, so whoever holds p can replace it with a claim until it confirms. (An ETH
        # refund from one RPC shares the state name but is handled by the rows below.)
        unconfirmed = (
            f"{source} reports the {chain} leg spent by a refund that is NOT CONFIRMED (see Counter-leg below): "
            "until it confirms, a claim with p can still replace it."
        )
        if kind == "TAKER_CLAIM":
            return (
                "COUNTER_LEG_REFUND_UNCONFIRMED",
                f"The taker CLAIMED the RXD covenant, so p is public in that spend. {unconfirmed} MAKER: claim "
                f"your {chain} with p now, at a fee that outbids the refund, before it confirms.",
            )
        who = (
            "The maker CSV-REFUNDED the RXD covenant."
            if kind == "MAKER_REFUND"
            else (
                "The RXD covenant is SPENT (by the taker's claim or the maker's CSV refund; this read cannot tell which)."
            )
        )
        return (
            "COUNTER_LEG_REFUND_UNCONFIRMED",
            f"{who} {unconfirmed} TAKER: keep watching your refund until it confirms, fee-bump it if it is slow, "
            f"and check it on a second, independent explorer — the maker holds p and can sweep your {chain} "
            "with it until then.",
        )
    if counter_leg_state == "LOCKED":
        if kind == "MAKER_REFUND":
            return (
                "COUNTER_LEG_LOCKED",
                f"The maker CSV-REFUNDED the RXD covenant and the {chain} leg is still LOCKED (see Counter-leg "
                f"below). TAKER: refund your {chain} now. {refund_advice}{no_timelock}",
            )
        if kind == "TAKER_CLAIM":
            return (
                "COUNTER_LEG_LOCKED",
                f"The taker CLAIMED the RXD covenant, so p is public in that spend, and the {chain} leg is still "
                f"LOCKED (see Counter-leg below). MAKER: claim your {chain} with p NOW, before the taker's "
                f"{chain} refund opens.",
            )
        return (
            "COUNTER_LEG_LOCKED",
            f"The RXD covenant is SPENT but the {chain} leg is still LOCKED (see Counter-leg below). The "
            f"covenant is spent by the taker's claim OR the maker's CSV refund. TAKER: if the maker "
            f"refunded, your {chain} is still locked — refund it now. {refund_advice}{no_timelock} "
            f"MAKER: if the taker claimed the covenant, claim your {chain} with p before the taker's "
            "refund opens.",
        )
    if kind == "MAKER_REFUND":
        return (
            "COVENANT_SPENT",
            f"The maker CSV-REFUNDED the RXD covenant; it does NOT mean the swap is over. TAKER: check your "
            f"{chain} leg (Counter-leg below; pass the counter-leg locator and endpoint if it was not checked). "
            f"If it is still unspent, refund it now. {refund_advice}{no_timelock}",
        )
    if kind == "TAKER_CLAIM":
        return (
            "COVENANT_SPENT",
            f"The taker CLAIMED the RXD covenant, so p is public in that spend; it does NOT mean the swap is "
            f"over. MAKER: check the {chain} leg (Counter-leg below) and claim it with p before the taker's "
            f"{chain} refund opens.",
        )
    return (
        "COVENANT_SPENT",
        f"The RXD covenant is SPENT — by the taker's claim or the maker's CSV refund; this read cannot "
        f"tell which, and it does NOT mean the swap is over. TAKER: check your {chain} leg (Counter-leg "
        f"below; pass the counter-leg locator and endpoint if it was not checked). If it is still "
        f"unspent, refund it now. {refund_advice}{no_timelock}",
    )


def classify_covenant(
    *,
    covenant_state: str,  # "live" | "spent" | "not_found"
    funding_height: int | None,
    now_height: int | None,
    t_rxd_blocks: int,
    counter_chain: str = "btc",
    counter_leg_state: str | None = None,
    refund_advice: str | None = None,
    counter_leg_source: str | None = None,
    covenant_spend_kind: str | None = None,
) -> tuple[str, str]:
    """Pure classifier → ``(situation, next_action)``. No network. ``funding_height``/``now_height``
    required only for the ``live`` case; ``counter_leg_state`` (a :class:`CounterLegStatus` state)
    only for the ``spent`` case, where it decides whether the swap is actually over.
    ``refund_advice`` (:func:`counter_leg_refund_advice`) and ``counter_leg_source`` (the server
    that answered) only shape the ``spent`` text. ``covenant_spend_kind`` (``TAKER_CLAIM`` /
    ``MAKER_REFUND`` / ``UNKNOWN``) is which branch spent the covenant, for the ``spent`` case.

    The block count is :func:`pyrxd.gravity.radiant_leg.blocks_to_claim_deadline` — the leg's own
    arithmetic, called rather than copied, so the screen shows the figure the claim is sized by."""
    if covenant_state == "not_found":
        return (
            "NOT_FUNDED",
            "Covenant not on chain — not yet funded, or funded then spent and pruned. "
            "Verify the SPK / --network, or the swap is already settled. That is one ElectrumX server's "
            "answer: if the counter-leg shows p revealed, read the covenant on a second, independent "
            "ElectrumX server before concluding anything.",
        )
    if covenant_state == "unidentified":
        return (
            "COVENANT_UNIDENTIFIED",
            "This read could not tell which output at the covenant script is this swap's covenant (see the "
            "reason above), and anyone can pay that script. Pass --covenant-outpoint TXID:VOUT — the covenant "
            "funding outpoint from your run log — or, if you pinned one, check it; then re-run.",
        )
    if covenant_state == "spent":
        return _covenant_spent(
            counter_chain,
            counter_leg_state,
            refund_advice=refund_advice,
            counter_leg_source=counter_leg_source,
            spend_kind=covenant_spend_kind,
        )
    # live
    if funding_height is None or now_height is None or funding_height > now_height:
        return ("LOCKED", "Covenant is live (unspent); heights unavailable to compute the refund deadline.")
    # Lazy: the leg module pulls in the covenant/fee stack, which `swap status` without
    # --check-chain never needs.
    from pyrxd.gravity.radiant_leg import blocks_to_claim_deadline

    refund_opens = funding_height + t_rxd_blocks
    blocks_left = blocks_to_claim_deadline(t_rxd_blocks, now_height - funding_height + 1)
    if blocks_left > 0:
        return (
            "LOCKED",
            f"Asset is locked and the covenant is live. The maker's CSV refund can be mined from RXD height "
            f"{refund_opens}: {blocks_left} block(s) remain in which only the taker's claim can be mined. "
            "If you are the TAKER and the maker has revealed the preimage (claimed their counter-leg), "
            "claim the asset now; otherwise keep watching.",
        )
    return (
        "REFUND_OPEN",
        f"REFUND WINDOW OPEN — the covenant is live and at least {t_rxd_blocks} blocks deep, so the maker's CSV "
        f"refund is valid now (it can be mined from RXD height {refund_opens}). The "
        "maker can CSV-refund the asset now. TAKER: claim IMMEDIATELY if you hold the preimage, or the "
        "maker reclaims it. MAKER: your refund is available.",
    )


async def _read_covenant(
    ctx: CliContext,
    spk_hex: str,
    hashlock_hex: str | None = None,
    *,
    pin_outpoint: str | None = None,
    expected_value: int | None = None,
    t_rxd_blocks: int | None = None,
) -> dict[str, Any]:
    """Read-only ElectrumX query: covenant liveness + funding height + current tip. Never broadcasts.

    The covenant is ONE output, found by :func:`~pyrxd.cli.swap_recovery.locate_covenant_funding`
    (``pin_outpoint`` when known, else the earliest-confirmed payment to the script, of
    ``expected_value`` when known) — never "any unspent output at the script". The script is a pure
    function of public terms, so other outputs can sit at it; whether the covenant is live, its
    value and its funding height are those of the identified output alone. Other outputs are
    counted (``ignored_outputs``) and change nothing else.

    For a SPENT covenant it also reads the spending transaction and records which branch took it
    (``covenant_spend``): without that, a maker's refund and a taker's claim are indistinguishable.
    A failure of that second read is reported as ``UNKNOWN`` with its reason, never raised — the
    liveness verdict above it is still worth printing.
    """
    async with ctx.make_client() as client:
        try:
            loc = await locate_covenant_funding(
                client, spk_hex, pin_outpoint=pin_outpoint, expected_value=expected_value
            )
        except CovenantUnidentified as exc:
            return {
                "covenant_state": "unidentified",
                "covenant_reason": str(exc),
                "funding_height": None,
                "depth": None,
                "value_photons": None,
                "now_height": None,
            }
        now_height = loc.tip_height
        out: dict[str, Any] = {
            "covenant_state": {"live": "live", "spent": "spent"}.get(loc.state, "not_found"),
            "covenant_outpoint": loc.outpoint,
            "covenant_identified_by": loc.identified_by,
            "ignored_outputs": loc.ignored_outputs,
            "funding_height": None,
            "depth": None,
            "value_photons": None,
            "now_height": now_height,
        }
        if loc.state == "absent" and loc.identified_by == "pinned":
            out["covenant_reason"] = (
                f"the pinned covenant outpoint {loc.outpoint} was not found: it is neither live at the covenant "
                "script nor in the script's history"
            )
        if loc.state == "live":
            # A funding height above the tip is two reads of a moving chain (a lagging endpoint),
            # not a depth; reported unmeasured rather than as zero or negative. An unconfirmed
            # covenant has no height (ElectrumX reports 0 or -1; the locator maps both to None).
            fh = loc.height
            out["funding_height"] = fh
            out["depth"] = (now_height - fh + 1) if fh is not None and fh <= now_height else None
            out["value_photons"] = loc.value
            return out
        history = list(loc.history)
        if loc.state == "spent":
            try:
                hashlock = bytes.fromhex(hashlock_hex) if hashlock_hex else None
            except ValueError:
                hashlock = None
            try:
                spend = await read_covenant_spend(
                    client,
                    spk_hex,
                    history,
                    hashlock=hashlock,
                    outpoint=loc.outpoint,
                    funding_height=loc.height,
                    t_rxd_blocks=t_rxd_blocks,
                )
            except Exception as exc:
                spend = CovenantSpend(
                    "UNKNOWN",
                    "the covenant's spending transaction could not be read: "
                    + describe_network_error(exc, scrub=electrumx_urls(ctx)),
                )
            out["covenant_spend"] = spend.to_dict()
        return out


# --------------------------------------------------------------------------- CLI


@click.group(name="swap")
def swap_group() -> None:
    """Same-chain RSWP orderbook (orders/reserve/post/take/cancel/refund) + cross-chain swap status.

    ``status`` and ``orders`` are read-only. ``reserve``/``post``/``take``/
    ``cancel``/``refund`` broadcast AFTER an explicit value confirmation
    (``--json`` requires ``--yes``) — see each command's help for what
    exactly is signed. ``reserve``/``refund`` are the v3 timelocked-refund
    covenant flows; ``post``/``take``/``cancel`` auto-detect a covenant-held
    UTXO and route to the matching v3 builder.
    """


@swap_group.command(name="status")
@click.option(
    "--swap-file",
    "swap_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a swap recovery JSON (e.g. ~/.gravity_dust_run_keys.json).",
)
@click.option(
    "--check-chain",
    is_flag=True,
    default=False,
    help="Also do a READ-ONLY query of the RXD covenant AND the counter-leg to classify the situation.",
)
@click.option("--btc-funding-outpoint", "btc_outpoint", default=None, help="BTC HTLC funding outpoint TXID:VOUT.")
@click.option("--btc-api-url", default=DEFAULT_BTC_API_URL, show_default=True, help="Esplora / mempool.space base URL.")
@click.option("--eth-contract", default=None, help="The swap's per-swap ETH HTLC contract address (0x…).")
@click.option("--eth-rpc-url", default=None, help="Ethereum JSON-RPC URL (read-only methods only).")
@click.option(
    "--covenant-outpoint",
    "covenant_outpoint",
    default=None,
    help="The RXD covenant's funding outpoint TXID:VOUT. Overrides the recovery file's rxd_covenant_outpoint; "
    "without either, the earliest-confirmed payment to the covenant script is taken as the covenant.",
)
@click.pass_obj
def swap_status_cmd(
    ctx: CliContext,
    swap_file: Path,
    check_chain: bool,
    btc_outpoint: str | None,
    btc_api_url: str,
    eth_contract: str | None,
    eth_rpc_url: str | None,
    covenant_outpoint: str | None,
) -> None:
    """Show a swap's identity, timelock deadlines, and (with --check-chain) the safe next action."""
    try:
        facts = parse_recovery_file(swap_file)
        # ValidationError is NOT a ValueError subclass (it derives from RxdSdkError), so the
        # extras parser needs naming here explicitly — otherwise a file shape it rejects would
        # escape as an unhandled exception instead of the clean "could not parse" message.
        extras = parse_recovery_extras(swap_file)
    except (ValueError, ValidationError, json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(f"could not parse swap file: {exc}") from exc
    pin = covenant_outpoint or extras.rxd_covenant_outpoint
    if check_chain and pin is not None:
        # Only where it is used: a malformed pin must not stop the offline identity view.
        pin_name = "--covenant-outpoint" if covenant_outpoint else "the recovery file's rxd_covenant_outpoint"
        try:
            parse_outpoint(pin, what=pin_name)
        except ValidationError as exc:
            msg = str(exc) if pin_name in str(exc) else f"{pin_name}: {exc}"
            raise click.ClickException(f"invalid {sanitize_terminal(msg, max_len=200)}") from exc
    # The covenant's amount IS its funded output's value for every variant, so it tells the covenant
    # from a payment of another value. For ft that holds because 1 photon = 1 token unit on Radiant
    # (security/units.py, TokenUnits): the FT covenant is built from the token amount and funded with
    # an output whose value is that amount, which is also what RadiantChainIO.find_covenant_utxo filters on.
    expected_value = recorded_covenant_value(facts.asset_variant, extras)

    payload: dict = {
        "swap_file": str(swap_file),
        "counter_chain": facts.counter_chain,
        "asset_variant": facts.asset_variant,
        "hashlock": facts.hashlock_hex,
        "rxd_network": facts.rxd_network,
        "covenant_spk_prefix": facts.rxd_covenant_spk[:24] + "…",
        "t_rxd_blocks": facts.t_rxd_blocks,
        "stage": facts.stage,
        "holds_secrets": facts.has_preimage or facts.has_keys,
    }
    if facts.counter_chain == "btc":
        payload["t_btc_blocks"] = facts.t_btc_blocks
        payload["btc_htlc_address"] = facts.btc_htlc_address
    else:
        payload["eth_chain"] = facts.eth_chain
        payload["eth_timeout_unix_s"] = facts.eth_timeout_unix_s

    if check_chain:
        try:
            chain = asyncio.run(
                _read_covenant(
                    ctx,
                    facts.rxd_covenant_spk,
                    facts.hashlock_hex,
                    pin_outpoint=pin,
                    expected_value=expected_value,
                    t_rxd_blocks=facts.t_rxd_blocks,
                )
            )
        except Exception as exc:  # surface any read failure as a clean CLI error
            raise click.ClickException(
                "--check-chain read failed: "
                + sanitize_terminal(describe_network_error(exc, scrub=electrumx_urls(ctx)), max_len=300)
            ) from exc
        # The counter-leg read is BEST-EFFORT and must never sink the covenant verdict below:
        # an unreachable third-party explorer is not a reason to deny an operator the RXD facts
        # they came for, mid-incident. Any failure is reported as an ERROR row, not raised.
        # It runs FIRST because a SPENT covenant cannot be classified without it: a maker's
        # refund and a taker's claim look identical from the covenant alone.
        try:
            counter = asyncio.run(
                read_counter_leg(
                    facts,
                    extras,
                    btc_outpoint=btc_outpoint,
                    btc_api_url=btc_api_url,
                    eth_contract=eth_contract,
                    eth_rpc_url=eth_rpc_url,
                )
            )
        except Exception as exc:
            counter = CounterLegStatus(
                chain=facts.counter_chain,
                state="ERROR",
                # Never ``{exc}``: an aiohttp error quotes the full URL, and these URLs carry API keys.
                reason="counter-leg read failed: "
                + describe_network_error(exc, btc_api_url if facts.counter_chain == "btc" else eth_rpc_url),
            )
        payload["counter_leg"] = counter.to_dict()

        situation, next_action = classify_covenant(
            covenant_state=chain["covenant_state"],
            funding_height=chain["funding_height"],
            now_height=chain["now_height"],
            t_rxd_blocks=facts.t_rxd_blocks,
            counter_chain=facts.counter_chain,
            counter_leg_state=counter.state,
            refund_advice=counter_leg_refund_advice(facts),
            counter_leg_source=counter.source,
            covenant_spend_kind=(chain.get("covenant_spend") or {}).get("kind"),
        )
        chain["situation"] = situation
        chain["next_action"] = next_action
        # Both fields only where a depth was MEASURED. `blocks_to_claim_deadline(t, None)` raises
        # TypeError, and a depth that was not measured must not be turned into a count either.
        if chain["covenant_state"] == "live" and chain["funding_height"] is not None and chain["depth"] is not None:
            from pyrxd.gravity.radiant_leg import blocks_to_claim_deadline

            chain["refund_opens_height"] = chain["funding_height"] + facts.t_rxd_blocks
            # `t_rxd - depth`: the refund is valid once the covenant is t_rxd deep (a CSV-N spend
            # is accepted at depth N). This field used to be `funding_height + t_rxd - tip`, one
            # block more — see the CHANGELOG.
            chain["blocks_to_refund"] = blocks_to_claim_deadline(facts.t_rxd_blocks, chain["depth"])
        payload["chain"] = chain
        payload["situation"] = situation  # top-level for quiet mode

    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
        return
    if ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="situation" if check_chain else "counter_chain"))
        return

    # Every field below is interpolated from the (untrusted) recovery file. Sanitize each so a crafted
    # file cannot inject ANSI/control sequences into the operator's terminal and spoof the rendered
    # status or the "next action" guidance (CLI-1). Numeric fields are int-typed (parse_recovery_file)
    # and safe as-is; only the free-form strings need escaping.
    _chain = sanitize_terminal(facts.counter_chain, max_len=16)
    lines = [
        f"Swap: {_chain.upper()}↔RXD  ({sanitize_terminal(facts.asset_variant, max_len=16)})   "
        f"stage={sanitize_terminal(facts.stage, max_len=32) or '?'}",
        f"  hashlock H : {sanitize_terminal(facts.hashlock_hex, max_len=64)}",
        f"  covenant   : {sanitize_terminal(facts.rxd_covenant_spk[:24])}…  "
        f"(rxd_network={sanitize_terminal(facts.rxd_network, max_len=16)})",
        f"  t_rxd      : {facts.t_rxd_blocks} blocks (Radiant refund / claim deadline window)",
    ]
    if facts.counter_chain == "btc":
        lines.append(
            f"  t_btc      : {facts.t_btc_blocks} blocks   "
            f"BTC HTLC: {sanitize_terminal(facts.btc_htlc_address, max_len=120)}"
        )
    else:
        lines.append(
            f"  eth        : {sanitize_terminal(facts.eth_chain, max_len=32)}   timeout_unix={facts.eth_timeout_unix_s}"
        )
    if facts.has_preimage or facts.has_keys:
        lines.append("  ⚠ this file holds keys/preimage — keep it mode 0600 and shred after the swap settles.")
    if check_chain:
        chain = payload["chain"]
        lines.append("")
        lines.append(f"On-chain (read-only): covenant {chain['covenant_state'].upper()}")
        if chain.get("covenant_reason"):
            lines.append(f"  reason     : {sanitize_terminal(chain['covenant_reason'], max_len=400)}")
        if chain.get("covenant_outpoint"):
            how = (
                "pinned by the recovery file / --covenant-outpoint"
                if chain.get("covenant_identified_by") == "pinned"
                else "the earliest-confirmed payment to the covenant script"
            )
            lines.append(f"  outpoint   : {sanitize_terminal(chain['covenant_outpoint'], max_len=80)}  ({how})")
        if chain.get("ignored_outputs"):
            n = chain["ignored_outputs"]
            if chain.get("covenant_identified_by") == "pinned":
                why = "none is the outpoint you pinned."
            elif chain["covenant_state"] == "live":
                why = (
                    "the earliest-confirmed one was taken as the covenant; pass --covenant-outpoint if it is not "
                    "this swap's."
                )
            else:
                why = "none carries the recorded covenant amount, so none was taken as the covenant."
            lines.append(f"  ⚠ {n} other output(s) are live at the covenant script, which anyone can pay: {why}")
        spend = chain.get("covenant_spend")
        if spend:
            lines.append(f"  spent by   : {spend['kind']} — {sanitize_terminal(spend['reason'], max_len=300)}")
        if chain["covenant_state"] == "live":
            lines.append(
                f"  funded@{chain['funding_height']} depth={chain['depth']} value={chain['value_photons']} ph"
                f"  tip={chain['now_height']}"
            )
        lines.append(f"  situation  : {chain['situation']}")
        lines.append(f"  next action: {chain['next_action']}")
        cl = payload["counter_leg"]
        lines.append("")
        # Every field here came off a third-party explorer / RPC, so it is untrusted input in
        # exactly the same sense the recovery file is — sanitize before it reaches the terminal.
        lines.append(f"Counter-leg ({sanitize_terminal(cl['chain'], max_len=8).upper()}): {cl['state']}")
        lines.append(f"  {sanitize_terminal(cl['reason'], max_len=400)}")
        if cl["claim_txid"]:
            lines.append(f"  claim tx   : {sanitize_terminal(cl['claim_txid'], max_len=80)}")
        if cl["preimage_available"]:
            lines.append("  ⇒ run `pyrxd swap recover-preimage` to extract p, then `pyrxd swap build-claim`.")
    else:
        lines.append("")
        lines.append("  (run with --check-chain for the live covenant state + safe next action)")
    click.echo(emit(payload, mode="human", human_lines=lines))
