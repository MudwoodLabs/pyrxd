"""``pyrxd swap recover-preimage`` / ``build-claim`` / ``build-refund`` — the cold toolkit.

**READ-ONLY. These commands never broadcast.** They print raw transaction hex; the
operator inspects it and broadcasts from their own node, at a fee they chose. That is
the whole design: the same posture as ``pyrxd swap status`` (see
:mod:`pyrxd.cli.swap_cmds`), which is why the cold path sits outside the external swap
audit gate.

The workflow this exists for
----------------------------
Radiant has neither RBF nor CPFP (:mod:`pyrxd.gravity.fee_policy`), so automation now
REFUSES to broadcast an unaffordable time-critical spend and pages the operator instead.
This is the page's other end::

    pyrxd swap status --swap-file KEYS --check-chain --btc-funding-outpoint TXID:0
        -> counter-leg says CLAIMED_PREIMAGE_REVEALED

    pyrxd swap recover-preimage --swap-file KEYS --btc-funding-outpoint TXID:0
        -> p (provenance-checked, scraped from the counterparty's own claim)

    pyrxd swap build-claim --swap-file KEYS --preimage <p> --fee-wif-file ~/.fee
        -> the decoded spend + the relay floor + the deadline-aware target + raw hex

    ...operator reads it, then broadcasts it themselves.

Every provenance and fee rule lives in :mod:`pyrxd.cli.swap_recovery`; this module is
flags, formatting, and error mapping only.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import click

from ..gravity.fee_policy import DeadlineFeePolicy, photons_per_kb_from_rxd_per_kb
from ..security.errors import NetworkError, ValidationError
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit, sanitize_terminal
from .swap_cmds import parse_recovery_file
from .swap_recovery import (
    ColdSpend,
    PreimageNotRevealed,
    PreimageRecovery,
    ProvenanceRefused,
    assert_covenant_matches,
    build_cold_claim,
    build_cold_refund,
    covenant_pkhs,
    fetch_btc_claim_bytes,
    fetch_eth_claim_artifacts,
    open_http_session,
    parse_outpoint,
    parse_recovery_extras,
    read_covenant_chain_state,
    read_fee_utxos,
    rebuild_covenant,
    recover_preimage_from_btc_claim,
    recover_preimage_from_eth_claim,
    select_fee_utxo,
)

DEFAULT_BTC_API_URL = "https://mempool.space"

_NEVER_BROADCAST = (
    "This command NEVER broadcasts. Verify the outputs and the fee above, then broadcast the hex "
    "yourself. Radiant has no RBF and no CPFP: once sent, this cannot be re-fee'd and squats on its "
    "own inputs for up to 8h."
)


# --------------------------------------------------------------------------- shared helpers


def _load(swap_file: Path) -> tuple[Any, Any]:
    """Parse the recovery file into (public facts, optional locator extras)."""
    try:
        # ValidationError is NOT a ValueError subclass (it derives from RxdSdkError), so the
        # extras parser has to be named in the tuple below explicitly.
        return parse_recovery_file(swap_file), parse_recovery_extras(swap_file)
    except (ValueError, ValidationError, json.JSONDecodeError, OSError) as exc:
        raise UserError(
            "could not parse the swap recovery file",
            cause=sanitize_terminal(str(exc), max_len=200),
            fix="point --swap-file at the JSON a swap harness wrote (it must carry hashlock_H + rxd_covenant_spk)",
        ) from exc


def _hashlock(facts: Any) -> bytes:
    try:
        h = bytes.fromhex(facts.hashlock_hex)
    except ValueError as exc:
        raise UserError("recovery file hashlock_H is not hex") from exc
    if len(h) != 32:
        raise UserError("recovery file hashlock_H must be 32 bytes")
    return h


def _fee_policy(relay_fee_rxd_per_kb: float | None, allow_below_floor: bool) -> DeadlineFeePolicy:
    """Build the fee policy, defaulting to the reference node's effective relay rate.

    The rate is NODE POLICY and it moves — read ``effective_minrelaytxfee`` from your own
    ``getmempoolinfo`` and pass it, rather than trusting the default.
    """
    try:
        if relay_fee_rxd_per_kb is None:
            return DeadlineFeePolicy(allow_below_protocol_floor=allow_below_floor)
        return DeadlineFeePolicy(
            relay_fee_per_kb=photons_per_kb_from_rxd_per_kb(relay_fee_rxd_per_kb),
            allow_below_protocol_floor=allow_below_floor,
        )
    except ValidationError as exc:
        raise UserError(
            "invalid --relay-fee-rxd-per-kb",
            cause=str(exc),
            fix="pass the rate your node reports as effective_minrelaytxfee (e.g. 0.10)",
        ) from exc


def _resolve_secret_wif(inline: str | None, from_file: str | None, env_name: str = "PYRXD_COLD_FEE_WIF") -> str:
    """Resolve the fee key through the watchtower's owner-only 0600 file gate.

    Reused rather than re-implemented so the cold path inherits the same
    symlink-proof / fstat-on-the-same-fd / owner-check discipline the tower's
    credential files get. Imported lazily — ``cli_secrets`` is package code with no
    heavy graph, but the CLI pays for nothing it did not invoke.
    """
    from ..gravity.watch.cli_secrets import resolve_secret

    try:
        wif = resolve_secret(inline, from_file, env_name, flag="--fee-wif")
    except ValidationError as exc:
        raise UserError("could not read the fee key", cause=str(exc)) from exc
    if not wif:
        raise UserError(
            "no fee key supplied",
            cause="the covenant permits a single output, so a separate RXD input must pay the miner fee",
            fix=f"pass --fee-wif-file PATH (mode 0600), or set {env_name}",
        )
    return wif.strip()


def _run(coro: Any) -> Any:
    try:
        return asyncio.run(coro)
    except (NetworkError, OSError) as exc:
        raise NetworkBoundaryError(
            "a chain read failed",
            cause=sanitize_terminal(f"{type(exc).__name__}: {exc}", max_len=300),
            fix="check the endpoint URL and your connectivity, then retry — nothing was broadcast",
        ) from exc


# --------------------------------------------------------------------------- recover-preimage


async def _recover(
    *,
    facts: Any,
    hashlock: bytes,
    btc_outpoint: str | None,
    btc_api_url: str,
    eth_contract: str | None,
    eth_rpc_url: str | None,
    offline_raw: bytes | None,
    timeout_s: float,
) -> PreimageRecovery:
    if offline_raw is not None:
        # OFFLINE mode. Provenance does NOT relax: without the funding outpoint any
        # transaction carrying a value that hashes to H would be accepted, which is
        # exactly the cross-swap-replay hole the online path closes.
        if not btc_outpoint:
            raise UserError(
                "--claim-tx-hex/--claim-tx-file requires --btc-funding-outpoint",
                cause="provenance is mandatory offline too: without the funding outpoint, a foreign "
                "transaction that merely shares the hashlock H would be accepted as this swap's claim",
                fix="pass --btc-funding-outpoint TXID:VOUT (the BTC HTLC output the counterparty spent)",
            )
        return recover_preimage_from_btc_claim(
            offline_raw, hashlock=hashlock, funding_outpoint=parse_outpoint(btc_outpoint)
        )

    if facts.counter_chain == "btc":
        if not btc_outpoint:
            raise UserError(
                "the BTC funding outpoint is required and not in the recovery file",
                cause="files written before the harnesses started persisting `btc_funding_outpoint` "
                "only printed it to the console",
                fix="pass --btc-funding-outpoint TXID:VOUT (from the run log or a block explorer)",
            )
        outpoint = parse_outpoint(btc_outpoint, what="--btc-funding-outpoint")
        session = await open_http_session()
        async with session:
            spent, spender, raw = await fetch_btc_claim_bytes(session, btc_api_url, outpoint, timeout_s=timeout_s)
        if not spent:
            raise PreimageNotRevealed(
                f"BTC funding outpoint {outpoint.txid}:{outpoint.vout} is UNSPENT — the counterparty has "
                "not claimed, so there is no preimage to recover yet."
            )
        if not raw:
            raise ProvenanceRefused(
                f"the outpoint is spent by {spender}, but its raw bytes are not retrievable from "
                f"{btc_api_url} yet. Refusing to proceed on an unverifiable transaction."
            )
        return recover_preimage_from_btc_claim(raw, hashlock=hashlock, funding_outpoint=outpoint, reported_txid=spender)

    if not eth_contract or not eth_rpc_url:
        raise UserError(
            "the ETH HTLC contract address and an RPC URL are required",
            cause="before the harness change only scripts/eth_swap_two_host.py persisted "
            "`eth_contract_address`, so older recovery files do not carry it",
            fix="pass --eth-contract 0x… and --eth-rpc-url https://…",
        )
    session = await open_http_session()
    async with session:
        tx, logs = await fetch_eth_claim_artifacts(
            session, eth_rpc_url, contract_address=eth_contract, timeout_s=timeout_s
        )
    if tx is None:
        raise PreimageNotRevealed(
            f"the HTLC contract {eth_contract} shows no retrievable claim activity — no preimage yet."
        )
    return recover_preimage_from_eth_claim(hashlock=hashlock, contract_address=eth_contract, claim_tx=tx, logs=logs)


@click.command(name="recover-preimage")
@click.option(
    "--swap-file",
    "swap_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a swap recovery JSON (supplies the hashlock H and which counter-chain to read).",
)
@click.option("--btc-funding-outpoint", "btc_outpoint", default=None, help="BTC HTLC funding outpoint TXID:VOUT.")
@click.option("--btc-api-url", default=DEFAULT_BTC_API_URL, show_default=True, help="Esplora / mempool.space base URL.")
@click.option("--eth-contract", default=None, help="The swap's per-swap ETH HTLC contract address (0x…).")
@click.option("--eth-rpc-url", default=None, help="Ethereum JSON-RPC URL (read-only methods only).")
@click.option("--claim-tx-hex", default=None, help="OFFLINE: the counterparty's raw claim tx hex (BTC).")
@click.option(
    "--claim-tx-file",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="OFFLINE: a file holding the counterparty's raw claim tx hex (BTC).",
)
@click.option("--timeout", "timeout_s", default=15.0, show_default=True, help="Per-request read timeout, seconds.")
@click.pass_obj
def swap_recover_preimage_cmd(
    ctx: CliContext,
    swap_file: Path,
    btc_outpoint: str | None,
    btc_api_url: str,
    eth_contract: str | None,
    eth_rpc_url: str | None,
    claim_tx_hex: str | None,
    claim_tx_file: Path | None,
    timeout_s: float,
) -> None:
    """Scrape the preimage p off the counter-chain and verify it. READ-ONLY.

    The preimage is taken ONLY from the counterparty's own on-chain claim, never from
    the recovery file's ``preimage_p_hex`` — on a maker's host that copy may still be a
    PRE-REVEAL secret, and "recovering" it would manufacture a claim the operator is not
    yet entitled to make. A chain-scraped p is already public, which is why printing it
    here is safe.

    Provenance is mandatory on every path, including ``--claim-tx-hex``: the bytes must
    re-derive to the reported spender txid AND spend this swap's funding outpoint before
    anything is scraped. A foreign transaction that merely shares the hashlock H is
    refused.
    """
    facts, extras = _load(swap_file)
    hashlock = _hashlock(facts)
    btc_outpoint = btc_outpoint or extras.btc_funding_outpoint
    eth_contract = eth_contract or extras.eth_contract_address

    offline_raw: bytes | None = None
    if claim_tx_hex and claim_tx_file:
        raise UserError("pass only one of --claim-tx-hex / --claim-tx-file")
    raw_hex = claim_tx_hex or (claim_tx_file.read_text().strip() if claim_tx_file else None)
    if raw_hex:
        try:
            offline_raw = bytes.fromhex(raw_hex.strip())
        except ValueError as exc:
            raise UserError("the supplied claim transaction is not valid hex") from exc

    try:
        rec = _run(
            _recover(
                facts=facts,
                hashlock=hashlock,
                btc_outpoint=btc_outpoint,
                btc_api_url=btc_api_url,
                eth_contract=eth_contract,
                eth_rpc_url=eth_rpc_url,
                offline_raw=offline_raw,
                timeout_s=timeout_s,
            )
        )
    except ProvenanceRefused as exc:
        raise UserError(
            "REFUSED on provenance — no preimage was taken",
            cause=sanitize_terminal(str(exc), max_len=400),
            fix="confirm --btc-funding-outpoint is THIS swap's funding output; a transaction that only "
            "shares the hashlock is not this swap's claim",
        ) from exc
    except PreimageNotRevealed as exc:
        raise UserError(
            "no preimage has been revealed yet",
            cause=sanitize_terminal(str(exc), max_len=400),
            fix="keep watching (`pyrxd swap status --check-chain`); if the covenant's CSV window opens "
            "first, the refund path is the one that applies",
        ) from exc
    except ValidationError as exc:
        raise UserError("preimage recovery failed", cause=sanitize_terminal(str(exc), max_len=400)) from exc

    payload: dict[str, Any] = {
        "counter_chain": rec.counter_chain,
        "hashlock": rec.hashlock_hex,
        "preimage_hex": rec.preimage_hex,
        "source": rec.source,
        "claim_txid": rec.claim_txid,
        "provenance_checks": list(rec.provenance),
        "broadcast": False,
    }
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
        return
    if ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="preimage_hex"))
        return
    lines = [
        f"Preimage RECOVERED from the {rec.counter_chain.upper()} counter-leg (read-only).",
        "",
        f"  hashlock H : {rec.hashlock_hex}",
        f"  preimage p : {rec.preimage_hex}",
        f"  source     : {sanitize_terminal(rec.source, max_len=48)}"
        f"   claim tx: {sanitize_terminal(rec.claim_txid, max_len=80) or '(offline)'}",
        "",
        "  provenance checks that PASSED:",
        *[f"    - {sanitize_terminal(c, max_len=200)}" for c in rec.provenance],
        "",
        "  p was scraped from the counterparty's own on-chain claim, so it is already PUBLIC.",
        "  Next: pyrxd swap build-claim --swap-file … --preimage " + rec.preimage_hex,
    ]
    click.echo(emit(payload, mode="human", human_lines=lines))


# --------------------------------------------------------------------------- cold spend builders


def _resolve_amount(variant: str, extras: Any, carrier_value: int, explicit: int | None) -> int:
    """The covenant's ``amount``/``nftCarrierValue`` parameter — self-checked downstream.

    Precedence: the explicit flag, then ``rxd_covenant_amount`` (which the harnesses now
    persist — older files predate it), then a derivation. For ``rxd``/``nft`` the value
    parameter IS the funded carrier value read from chain; for ``ft`` it is the token
    amount (``asset_ft_amount``), which the carrier value does not encode.

    Any wrong answer is caught by the SPK equality check in
    :func:`~pyrxd.cli.swap_recovery.assert_covenant_matches`, so this is a convenience
    default and never a trusted input.
    """
    if explicit is not None:
        return explicit
    if extras.rxd_covenant_amount is not None:
        return int(extras.rxd_covenant_amount)
    if variant == "ft":
        if extras.asset_ft_amount is None:
            raise UserError(
                "the FT covenant amount is not in the recovery file",
                cause="the covenant SPK is built from the FT amount, and files written before "
                "`rxd_covenant_amount` was persisted do not carry it",
                fix="pass --covenant-amount <ft amount>",
            )
        return int(extras.asset_ft_amount)
    return carrier_value


async def _prepare(
    ctx: CliContext,
    *,
    swap_file: Path,
    facts: Any,
    extras: Any,
    taker_pkh_hex: str | None,
    maker_pkh_hex: str | None,
    covenant_amount: int | None,
    genesis_ref: str | None,
    fee_wif: str,
    fee_utxo: str | None,
    policy: DeadlineFeePolicy,
    kind: str,
    allow_overpay: bool = False,
) -> tuple[Any, Any, Any]:
    """Read the covenant + fee UTXOs, rebuild the covenant, and pick a fee input.

    Reads only: ``get_utxos`` / ``get_history`` / ``get_tip_height``. The client's
    ``broadcast`` method is never called on this path.
    """
    async with ctx.make_client() as client:
        chain = await read_covenant_chain_state(client, facts.rxd_covenant_spk)
        amount = _resolve_amount(facts.asset_variant, extras, chain.carrier_value, covenant_amount)
        taker_pkh, maker_pkh = covenant_pkhs(swap_file, taker_pkh_hex=taker_pkh_hex, maker_pkh_hex=maker_pkh_hex)
        covenant = rebuild_covenant(
            asset_variant=facts.asset_variant,
            taker_pkh=taker_pkh,
            maker_pkh=maker_pkh,
            hashlock=_hashlock(facts),
            refund_csv=facts.t_rxd_blocks,
            amount=amount,
            genesis_ref=genesis_ref or extras.asset_genesis_ref,
        )
        assert_covenant_matches(covenant, facts.rxd_covenant_spk)

        utxos = await read_fee_utxos(client, fee_wif)
    # Selecting a fee input needs a size, but the size is only knowable once the transaction
    # is built and signed — and it is built FROM the input. So the bar is set against an
    # over-estimate and the exact requirement is re-measured against len(tx.serialize())
    # afterwards; over-estimating only picks a marginally larger input, which is the safe
    # direction, while under-estimating would select an input the builder then rejects.
    #
    # 300 bytes covers the RXD shapes measured on this tree (claim 267 / refund 234). The
    # only part that varies by asset variant is the single output's holder script (RXD 25
    # bytes, NFT 63, FT 75), so adding its real length keeps the estimate above every
    # variant rather than only the one that happened to be measured.
    holder = covenant.taker_holder_script if kind == "claim" else covenant.maker_holder_script
    size_estimate = 300 + len(holder)
    floor = policy.min_relay_fee(size_estimate)
    # The urgency premium applies to the CLAIM only: a CSV refund has no closing window
    # (see build_cold_refund), so targeting a premium for it would select a needlessly
    # large input and burn the difference as fee.
    blocks_left = max(0, facts.t_rxd_blocks - chain.confirmations) if kind == "claim" else None
    target = policy.required_fee(size_estimate, blocks_to_deadline=blocks_left)
    chosen = select_fee_utxo(utxos, floor=floor, target=target, explicit=fee_utxo, allow_overpay=allow_overpay)
    return covenant, chain, chosen


def _spend_payload(spend: ColdSpend, facts: Any) -> dict[str, Any]:
    payload = spend.to_dict()
    payload["asset_variant"] = facts.asset_variant
    payload["rxd_network"] = facts.rxd_network
    return payload


def _spend_lines(spend: ColdSpend, *, tip_height: int) -> list[str]:
    fee_state = (
        "clears the deadline-aware TARGET"
        if spend.clears_target
        else (
            "above the relay FLOOR but BELOW the target — inclusion may be slow"
            if spend.clears_floor
            else "BELOW THE RELAY FLOOR"
        )
    )
    # An overpay CLEARS the target, so the old verdict read as reassuring while the operator
    # burned three orders of magnitude more than the requirement (audit B4). Name it here, in
    # the same line an operator reads to decide whether to send this.
    if spend.is_overpay:
        fee_state = f"OVERPAY — {spend.overpay_multiple:.0f}x the requirement; the WHOLE input is burned as fee"
    # The SAME number means opposite things on the two branches, and conflating them is a
    # way to get an operator killed: on the REFUND the covenant's CSV is a GATE (a node
    # rejects a non-final spend), while on the CLAIM the claim branch has no timelock at
    # all — that same depth is the DEADLINE, the point at which the counterparty's refund
    # opens and the asset is lost. So the refund reports maturity, and the claim reports
    # depth plus how long is left; neither borrows the other's wording.
    #
    # An UNRESOLVED depth gets its own wording on both branches. ``csv_confirmations`` is 0
    # there because nothing measured it — two chain reads disagreed — not because the
    # covenant is 0-conf, and printing "0 confirmations" would state as fact a number this
    # run never established.
    if spend.depth_unresolved:
        timing = (
            f"  depth      : UNRESOLVED — two chain reads disagreed, so the covenant's depth was never "
            f"measured (the maker's CSV refund branch opens at {spend.csv_required})",
            "  deadline   : treated as ALREADY HERE — the fee is sized at maximum urgency rather than "
            "assuming time that was not measured. Re-run against a single, caught-up endpoint for a "
            "real depth before you rely on this number.",
        )
    elif spend.kind == "refund":
        timing = (
            "  csv        : "
            + (
                f"MATURE ({spend.csv_confirmations}/{spend.csv_required} confirmations) — spendable now"
                if spend.csv_mature
                else f"IMMATURE ({spend.csv_confirmations}/{spend.csv_required} confirmations, "
                f"{spend.csv_required - spend.csv_confirmations} block(s) to go)"
            ),
            "  deadline   : none — a CSV refund has no closing window once it opens",
        )
    else:
        timing = (
            f"  depth      : {spend.csv_confirmations} confirmation(s); the maker's CSV refund "
            f"branch opens at {spend.csv_required}",
            f"  deadline   : {spend.blocks_to_deadline} block(s) — this must be MINED, not merely "
            "broadcast, before then",
        )
    lines = [
        f"COLD HTLC covenant {spend.kind.upper()} — BUILT, NOT BROADCAST.",
        "",
        f"  covenant   : {spend.covenant_outpoint}   carrier={spend.carrier_value} photons   tip={tip_height}",
        *timing,
        f"  fee input  : {spend.fee_outpoint}   {spend.fee_photons} photons",
        "               (the covenant permits ONE output, so there is no change — the WHOLE input is the fee)",
        f"  size       : {spend.size_bytes} bytes (serialized, post-signing — what the node measures)",
        f"  relay floor: {spend.relay_floor_photons} photons   <- below this the node rejects outright",
        f"  target     : {spend.target_photons} photons   (x{spend.urgency_multiplier:.2f} urgency premium)",
        f"  fee verdict: {fee_state}",
        "",
        "  outputs:",
    ]
    lines.extend(
        f"    [{o['index']}] {o['value_photons']} photons -> {o['pays']}\n         spk {o['scriptpubkey_hex']}"
        for o in spend.outputs
    )
    lines += [
        "",
        f"  txid (if mined as-is): {spend.txid}",
        "",
        "  raw transaction hex:",
        spend.raw_hex,
        "",
        f"  {_NEVER_BROADCAST}",
    ]
    if spend.kind == "refund" and not spend.csv_mature:
        lines.append("  ⚠ THE CSV IS NOT MATURE — a node will reject this refund until it is. Do not send it yet.")
    if spend.kind == "claim" and spend.csv_mature:
        lines.append(
            "  ⚠ THE MAKER'S REFUND WINDOW IS ALREADY OPEN — this claim is RACING their refund. "
            "It is still valid and worth sending, but send it now and expect to lose the race."
        )
    if spend.is_overpay:
        lines.append(
            f"  ⚠ OVERPAY: this spend pays {spend.fee_photons} photons for a ~{spend.target_photons}-photon "
            f"requirement ({spend.overpay_multiple:.0f}x). The covenant permits ONE output, so there is no "
            "change — the difference is GONE to the miner. Carve a smaller fee UTXO unless this is deliberate."
        )
    if not spend.clears_floor:  # pragma: no cover - see below
        # Unreachable today: the builders themselves refuse below the relay floor
        # (`_assert_fee_clears_relay_floor`), so a spend that got this far has cleared it.
        # Kept as belt-and-braces because the consequence of the pair drifting apart is an
        # operator broadcasting an un-relayable, un-bumpable transaction.
        lines.append("  ⚠ THE FEE IS BELOW THE RELAY FLOOR — this will not relay. Fund a larger fee UTXO.")
    return lines


def _emit_spend(ctx: CliContext, spend: ColdSpend, facts: Any, chain: Any) -> None:
    payload = _spend_payload(spend, facts)
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
        return
    if ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="raw_hex"))
        return
    click.echo(emit(payload, mode="human", human_lines=_spend_lines(spend, tip_height=chain.tip_height)))


def _cold_options(f: Any) -> Any:
    """Flags shared by ``build-claim`` and ``build-refund``."""
    for opt in reversed(
        [
            click.option(
                "--swap-file",
                "swap_file",
                required=True,
                type=click.Path(exists=True, dir_okay=False, path_type=Path),
                help="Path to a swap recovery JSON.",
            ),
            click.option("--fee-wif", default=None, help="Fee key WIF (visible in ps — prefer --fee-wif-file)."),
            click.option("--fee-wif-file", default=None, help="File holding the fee key WIF (mode 0600, owner-only)."),
            click.option("--fee-utxo", default=None, help="Use this fee input TXID:VOUT instead of auto-selecting."),
            click.option("--covenant-amount", type=int, default=None, help="The covenant's amount parameter."),
            click.option("--genesis-ref", default=None, help="FT/NFT asset genesis ref TXID:VOUT."),
            click.option("--taker-pkh", default=None, help="Taker RXD pkh (40 hex) if the file lacks the key."),
            click.option("--maker-pkh", default=None, help="Maker RXD pkh (40 hex) if the file lacks the key."),
            click.option(
                "--relay-fee-rxd-per-kb",
                type=float,
                default=None,
                help="Your node's effective_minrelaytxfee (RXD/kB). Default: the reference 0.10.",
            ),
            click.option(
                "--allow-below-protocol-floor",
                is_flag=True,
                default=False,
                help="Permit a relay rate under the chain floor (regtest / a chain you control).",
            ),
            click.option(
                "--allow-overpay",
                is_flag=True,
                default=False,
                help="Burn a fee UTXO far larger than the requirement. The covenant permits ONE "
                "output, so the WHOLE input is the miner fee — without this the build refuses.",
            ),
            click.option(
                "--allow-unconfirmed",
                is_flag=True,
                default=False,
                help="Build against a 0-conf (mempool-only) covenant. The spend is only as good "
                "as its parent, and Radiant has no RBF/CPFP to repair it.",
            ),
        ]
    ):
        f = opt(f)
    return f


@click.command(name="build-claim")
@_cold_options
@click.option("--preimage", required=True, help="The preimage p (64 hex) from `pyrxd swap recover-preimage`.")
@click.pass_obj
def swap_build_claim_cmd(
    ctx: CliContext,
    swap_file: Path,
    fee_wif: str | None,
    fee_wif_file: str | None,
    fee_utxo: str | None,
    covenant_amount: int | None,
    genesis_ref: str | None,
    taker_pkh: str | None,
    maker_pkh: str | None,
    relay_fee_rxd_per_kb: float | None,
    allow_below_protocol_floor: bool,
    allow_overpay: bool,
    allow_unconfirmed: bool,
    preimage: str,
) -> None:
    """Build the TAKER's claim spend and PRINT its hex. READ-ONLY — never broadcasts.

    Prints the decoded output, the fee, the node's relay floor, the deadline-aware
    target and the CSV state alongside the hex, so a human can size the fee
    deliberately before sending it. The builder itself refuses to return a spend below
    the relay floor (there is no post-broadcast remedy on Radiant).

    The preimage must come from ``recover-preimage``, i.e. from the counterparty's own
    on-chain claim — this command deliberately does not read the recovery file's
    ``preimage_p_hex``.
    """
    facts, extras = _load(swap_file)
    try:
        p = bytes.fromhex(preimage.strip())
    except ValueError as exc:
        raise UserError("--preimage is not valid hex") from exc
    if len(p) != 32:
        raise UserError("--preimage must be 32 bytes (64 hex chars)")
    wif = _resolve_secret_wif(fee_wif, fee_wif_file)
    policy = _fee_policy(relay_fee_rxd_per_kb, allow_below_protocol_floor)
    try:
        covenant, chain, utxo = _run(
            _prepare(
                ctx,
                swap_file=swap_file,
                facts=facts,
                extras=extras,
                taker_pkh_hex=taker_pkh,
                maker_pkh_hex=maker_pkh,
                covenant_amount=covenant_amount,
                genesis_ref=genesis_ref,
                fee_wif=wif,
                fee_utxo=fee_utxo,
                policy=policy,
                kind="claim",
                allow_overpay=allow_overpay,
            )
        )
        spend = build_cold_claim(
            covenant=covenant,
            chain=chain,
            preimage=p,
            fee_wif=wif,
            fee_utxo=utxo,
            policy=policy,
            allow_unconfirmed=allow_unconfirmed,
        )
    except ValidationError as exc:
        raise UserError(
            "could not build the claim spend",
            cause=sanitize_terminal(str(exc), max_len=500),
            fix="nothing was broadcast — correct the input above and re-run",
        ) from exc
    _emit_spend(ctx, spend, facts, chain)


@click.command(name="build-refund")
@_cold_options
@click.option(
    "--allow-immature",
    is_flag=True,
    default=False,
    help="Pre-build the refund before its CSV matures (build now, broadcast at maturity).",
)
@click.pass_obj
def swap_build_refund_cmd(
    ctx: CliContext,
    swap_file: Path,
    fee_wif: str | None,
    fee_wif_file: str | None,
    fee_utxo: str | None,
    covenant_amount: int | None,
    genesis_ref: str | None,
    taker_pkh: str | None,
    maker_pkh: str | None,
    relay_fee_rxd_per_kb: float | None,
    allow_below_protocol_floor: bool,
    allow_overpay: bool,
    allow_unconfirmed: bool,
    allow_immature: bool,
) -> None:
    """Build the MAKER's CSV refund spend and PRINT its hex. READ-ONLY — never broadcasts.

    Refuses by default while the covenant's relative timelock is immature (a node would
    reject the spend as non-final, and with no RBF it would then squat on the covenant
    for up to 8h). ``--allow-immature`` pre-builds it anyway, which is the legitimate
    cold workflow: assemble and inspect now, broadcast the moment the CSV opens.

    No urgency premium is applied: a CSV refund has no closing window, so paying one
    would burn fee for urgency that does not exist. The relay floor still binds.
    """
    facts, extras = _load(swap_file)
    wif = _resolve_secret_wif(fee_wif, fee_wif_file)
    policy = _fee_policy(relay_fee_rxd_per_kb, allow_below_protocol_floor)
    try:
        covenant, chain, utxo = _run(
            _prepare(
                ctx,
                swap_file=swap_file,
                facts=facts,
                extras=extras,
                taker_pkh_hex=taker_pkh,
                maker_pkh_hex=maker_pkh,
                covenant_amount=covenant_amount,
                genesis_ref=genesis_ref,
                fee_wif=wif,
                fee_utxo=fee_utxo,
                policy=policy,
                kind="refund",
                allow_overpay=allow_overpay,
            )
        )
        spend = build_cold_refund(
            covenant=covenant,
            chain=chain,
            fee_wif=wif,
            fee_utxo=utxo,
            policy=policy,
            allow_immature=allow_immature,
            allow_unconfirmed=allow_unconfirmed,
        )
    except ValidationError as exc:
        raise UserError(
            "could not build the refund spend",
            cause=sanitize_terminal(str(exc), max_len=500),
            fix="nothing was broadcast — correct the input above and re-run",
        ) from exc
    _emit_spend(ctx, spend, facts, chain)
