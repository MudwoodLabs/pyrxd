"""Read-only ``pyrxd swap`` CLI — inspect a Gravity cross-chain swap from its recovery file.

``swap status --swap-file PATH`` parses the recovery JSON the swap harnesses write (BTC↔RXD or
ETH↔RXD) and prints the swap's identity + timelock deadlines. With ``--check-chain`` it additionally
does a **read-only** ElectrumX query of the RXD covenant to classify the live situation and the single
safe next action. **It never broadcasts** — so it sidesteps the swap audit gate entirely.

The recovery file holds WIFs + the preimage; this command reads them only to derive public facts and
**never echoes any secret** — output carries booleans (``has_preimage``/``has_keys``) and a hygiene
reminder, not key material.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import click

from .context import CliContext
from .format import emit

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
    eth_timeout_unix_s: int | None = None
    eth_amount_wei: int | None = None
    # asset detail (ft/nft)
    asset_genesis_ref: str | None = None
    asset_ft_amount: int | None = None


_SECRET_KEY_MARKERS = ("wif", "key_hex", "secret", "preimage", "privkey")


def parse_recovery_file(path: Path) -> SwapFacts:
    """Parse a harness recovery JSON into public :class:`SwapFacts`. Raises ``ValueError`` on a file
    that does not look like a swap recovery file (missing the covenant SPK + hashlock)."""
    d = json.loads(path.read_text())
    if not isinstance(d, dict):
        raise ValueError("recovery file is not a JSON object")
    hashlock = d.get("hashlock_H")
    spk = d.get("rxd_covenant_spk")
    if not hashlock or not spk:
        raise ValueError("not a swap recovery file (missing hashlock_H / rxd_covenant_spk)")
    t_rxd = d.get("t_rxd_blocks")
    if not isinstance(t_rxd, int):
        raise ValueError("recovery file missing integer t_rxd_blocks")

    is_eth = ("eth_chain" in d) or (d.get("counter_chain") == "eth")
    has_secret = any(any(m in k.lower() for m in _SECRET_KEY_MARKERS) for k in d)
    return SwapFacts(
        counter_chain="eth" if is_eth else "btc",
        hashlock_hex=str(hashlock),
        asset_variant=str(d.get("asset_variant", "rxd")),
        rxd_covenant_spk=str(spk),
        rxd_network=str(d.get("rxd_network", "bc")),
        t_rxd_blocks=t_rxd,
        stage=d.get("stage"),
        has_preimage="preimage_p_hex" in d,
        has_keys=has_secret,
        t_btc_blocks=d.get("t_btc_blocks"),
        btc_htlc_address=d.get("btc_htlc_address"),
        btc_network=d.get("btc_network"),
        eth_chain=d.get("eth_chain"),
        eth_timeout_unix_s=d.get("eth_timeout_unix_s"),
        eth_amount_wei=d.get("eth_amount_wei"),
        asset_genesis_ref=d.get("asset_genesis_ref"),
        asset_ft_amount=d.get("asset_ft_amount"),
    )


# --------------------------------------------------------------------------- covenant classification


def electrumx_script_hash(spk_hex: str) -> str:
    """ElectrumX ``script_hash`` for a raw scriptPubKey: ``sha256(spk)`` reversed (display order)."""
    return hashlib.sha256(bytes.fromhex(spk_hex)).digest()[::-1].hex()


def classify_covenant(
    *,
    covenant_state: str,  # "live" | "spent" | "not_found"
    funding_height: int | None,
    now_height: int | None,
    t_rxd_blocks: int,
) -> tuple[str, str]:
    """Pure classifier → ``(situation, next_action)``. No network. ``funding_height``/``now_height``
    required only for the ``live`` case. The refund (CSV) opens at ``funding_height + t_rxd_blocks``."""
    if covenant_state == "not_found":
        return (
            "NOT_FUNDED",
            "Covenant not on chain — not yet funded, or funded then spent and pruned. "
            "Verify the SPK / --network, or the swap is already settled.",
        )
    if covenant_state == "spent":
        return (
            "SETTLED",
            "Covenant outpoint is SPENT — the swap settled (taker claimed the asset) or was refunded. "
            "Read the spending tx to see which; no further action.",
        )
    # live
    if funding_height is None or now_height is None:
        return ("LOCKED", "Covenant is live (unspent); heights unavailable to compute the refund deadline.")
    refund_opens = funding_height + t_rxd_blocks
    blocks_left = refund_opens - now_height
    if blocks_left > 0:
        return (
            "LOCKED",
            f"Asset is locked and the covenant is live. The maker's CSV refund opens at RXD height "
            f"{refund_opens} ({blocks_left} blocks away). If you are the TAKER and the maker has revealed "
            "the preimage (claimed their counter-leg), claim the asset now; otherwise keep watching.",
        )
    return (
        "REFUND_OPEN",
        f"REFUND WINDOW OPEN — the covenant is live but past t_rxd (height {refund_opens} reached). The "
        "maker can CSV-refund the asset now. TAKER: claim IMMEDIATELY if you hold the preimage, or the "
        "maker reclaims it. MAKER: your refund is available.",
    )


async def _read_covenant(ctx: CliContext, spk_hex: str) -> dict:
    """Read-only ElectrumX query: covenant liveness + funding height + current tip. Never broadcasts."""
    sh = electrumx_script_hash(spk_hex)
    async with ctx.make_client() as client:
        utxos = await client.get_utxos(sh)
        now_height = int(await client.get_tip_height())
        if utxos:
            funding_height = min(int(u.height) for u in utxos if u.height) if any(u.height for u in utxos) else None
            return {
                "covenant_state": "live",
                "funding_height": funding_height,
                "depth": (now_height - funding_height + 1) if funding_height else None,
                "value_photons": sum(int(u.value) for u in utxos),
                "now_height": now_height,
            }
        history = await client.get_history(sh)
        return {
            "covenant_state": "spent" if history else "not_found",
            "funding_height": None,
            "depth": None,
            "value_photons": None,
            "now_height": now_height,
        }


# --------------------------------------------------------------------------- CLI


@click.group(name="swap")
def swap_group() -> None:
    """Inspect Gravity cross-chain swaps (read-only — never broadcasts)."""


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
    help="Also do a READ-ONLY ElectrumX query of the RXD covenant to classify the live situation.",
)
@click.pass_obj
def swap_status_cmd(ctx: CliContext, swap_file: Path, check_chain: bool) -> None:
    """Show a swap's identity, timelock deadlines, and (with --check-chain) the safe next action."""
    try:
        facts = parse_recovery_file(swap_file)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(f"could not parse swap file: {exc}") from exc

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
            chain = asyncio.run(_read_covenant(ctx, facts.rxd_covenant_spk))
        except Exception as exc:  # surface any read failure as a clean CLI error
            raise click.ClickException(f"--check-chain read failed: {type(exc).__name__}: {exc}") from exc
        situation, next_action = classify_covenant(
            covenant_state=chain["covenant_state"],
            funding_height=chain["funding_height"],
            now_height=chain["now_height"],
            t_rxd_blocks=facts.t_rxd_blocks,
        )
        chain["situation"] = situation
        chain["next_action"] = next_action
        if chain["covenant_state"] == "live" and chain["funding_height"] is not None:
            chain["refund_opens_height"] = chain["funding_height"] + facts.t_rxd_blocks
            chain["blocks_to_refund"] = chain["refund_opens_height"] - chain["now_height"]
        payload["chain"] = chain
        payload["situation"] = situation  # top-level for quiet mode

    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
        return
    if ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="situation" if check_chain else "counter_chain"))
        return

    lines = [
        f"Swap: {facts.counter_chain.upper()}↔RXD  ({facts.asset_variant})   stage={facts.stage or '?'}",
        f"  hashlock H : {facts.hashlock_hex}",
        f"  covenant   : {facts.rxd_covenant_spk[:24]}…  (rxd_network={facts.rxd_network})",
        f"  t_rxd      : {facts.t_rxd_blocks} blocks (Radiant refund / claim deadline window)",
    ]
    if facts.counter_chain == "btc":
        lines.append(f"  t_btc      : {facts.t_btc_blocks} blocks   BTC HTLC: {facts.btc_htlc_address}")
    else:
        lines.append(f"  eth        : {facts.eth_chain}   timeout_unix={facts.eth_timeout_unix_s}")
    if facts.has_preimage or facts.has_keys:
        lines.append("  ⚠ this file holds keys/preimage — keep it mode 0600 and shred after the swap settles.")
    if check_chain:
        chain = payload["chain"]
        lines.append("")
        lines.append(f"On-chain (read-only): covenant {chain['covenant_state'].upper()}")
        if chain["covenant_state"] == "live":
            lines.append(
                f"  funded@{chain['funding_height']} depth={chain['depth']} value={chain['value_photons']} ph"
                f"  tip={chain['now_height']}"
            )
        lines.append(f"  situation  : {chain['situation']}")
        lines.append(f"  next action: {chain['next_action']}")
    else:
        lines.append("")
        lines.append("  (run with --check-chain for the live covenant state + safe next action)")
    click.echo(emit(payload, mode="human", human_lines=lines))
