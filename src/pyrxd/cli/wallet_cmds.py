"""``pyrxd wallet …`` subcommand group.

Cut 1 commands:
  wallet new       Generate a fresh BIP39 mnemonic + HdWallet.
  wallet load      Validate that an existing wallet decrypts.
  wallet info      Show local-only wallet stats (no network).

Cut 3 (deferred):
  wallet export-xpub  Print account xpub for watch-only use.
"""

from __future__ import annotations

import asyncio
from typing import cast

import click

from ..constants import Network
from ..hd.bip39 import mnemonic_from_entropy
from ..hd.discovery import DEFAULT_ACCOUNTS, DEFAULT_COIN_TYPES, coin_type_label, discover
from ..hd.wallet import HdWallet
from ..security.errors import NetworkError, ValidationError
from ..security.rng import secure_random_bytes
from ..utils import validate_address
from ..wallet import DEFAULT_FEE_RATE
from .context import CliContext
from .errors import NetworkBoundaryError, UserError, WalletDecryptError
from .format import emit, format_photons
from .prompts import (
    confirm_action,
    prompt_mnemonic_input,
    prompt_passphrase_input,
    show_mnemonic,
)


def _parse_int_csv(value: str, *, flag: str) -> list[int]:
    """Parse a comma-separated list of non-negative ints (e.g. ``0,512,236``)."""
    out: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            n = int(part)
        except ValueError as exc:
            raise UserError(
                f"invalid {flag} value {part!r}",
                cause="expected a comma-separated list of integers",
                fix=f"e.g. {flag} 0,512,236",
            ) from exc
        if n < 0:
            raise UserError(f"{flag} values must be non-negative (got {n})")
        out.append(n)
    if not out:
        raise UserError(f"{flag} must contain at least one value")
    return out


@click.group(name="wallet")
def wallet_group() -> None:
    """Create, load, and inspect HD wallets."""


@wallet_group.command(name="new")
@click.option(
    "--mnemonic-words",
    type=click.Choice(["12", "24"]),
    default="12",
    help="BIP39 word count (default 12).",
)
@click.option(
    "--passphrase/--no-passphrase",
    default=False,
    help="Prompt for an optional BIP39 passphrase.",
)
@click.option(
    "--no-clipboard-warning",
    is_flag=True,
    default=False,
    envvar="PYRXD_NO_CLIPBOARD_WARNING",
    help="Skip the clipboard hygiene prompt (also: PYRXD_NO_CLIPBOARD_WARNING=1).",
)
@click.pass_obj
def wallet_new(ctx: CliContext, mnemonic_words: str, passphrase: bool, no_clipboard_warning: bool) -> None:
    """Generate a fresh BIP39 mnemonic + HdWallet."""
    ok, why = ctx.is_destructive_mode_safe()
    if not ok:
        raise UserError(why or "destructive op without --yes in --json mode")

    if ctx.wallet_path.exists():
        raise UserError(
            f"wallet already exists at {ctx.wallet_path}",
            cause="refusing to overwrite an existing wallet file",
            fix=f"choose a different --wallet path, or remove {ctx.wallet_path} first",
        )

    word_count = int(mnemonic_words)
    # 12 words = 128 bits entropy; 24 words = 256 bits.
    entropy_n = 16 if word_count == 12 else 32
    mnemonic = mnemonic_from_entropy(secure_random_bytes(entropy_n))

    # Derive at the coin type recorded in config (written by `setup
    # --coin-type`). Defaults to 512 (SLIP-0044). Persisted into the
    # wallet file by HdWallet so later `load` calls derive the same path.
    coin_type = ctx.config.coin_type

    # In JSON mode: emit the mnemonic as JSON without the gate. The user
    # passed --yes deliberately, so we trust them. In any other mode,
    # show the box + Enter gate.
    if ctx.output_mode == "json":
        passphrase_str = ""  # nosec B105 — empty string is the BIP39 spec default, not a hardcoded secret
        if passphrase:
            passphrase_str = prompt_passphrase_input(optional=True)
        wallet = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase_str, coin_type=coin_type)
        wallet.save(ctx.wallet_path)
        click.echo(
            emit(
                {
                    "mnemonic": mnemonic,
                    "wallet_path": str(ctx.wallet_path),
                    "address": wallet.next_receive_address(),
                    "coin_type": wallet.coin_type,
                    "path": f"m/44'/{wallet.coin_type}'/{wallet.account}'",
                },
                mode="json",
            )
        )
        return

    show_mnemonic(mnemonic.split(), ctx=ctx)
    if not no_clipboard_warning:
        click.echo("")
        click.echo(
            "  Some clipboard managers retain copy/paste history. If you copied\n"
            "  the mnemonic to your clipboard, clear your clipboard manager now.\n"
            "  (KDE Klipper, GNOME clipboard, etc.)"
        )
        click.pause("  Press Enter to continue, or Ctrl-C to abort.")
    passphrase_str = ""  # nosec B105 — empty string is the BIP39 spec default, not a hardcoded secret
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=True)
    wallet = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase_str, coin_type=coin_type)
    wallet.save(ctx.wallet_path)
    next_addr = wallet.next_receive_address()

    if ctx.output_mode == "quiet":
        click.echo(emit({"address": next_addr}, mode="quiet", quiet_field="address"))
        return

    click.echo("")
    click.echo(f"Wallet saved to {ctx.wallet_path}")
    click.echo(f"Derivation path: m/44'/{wallet.coin_type}'/{wallet.account}'")
    click.echo(f"First receive address: {next_addr}")


@wallet_group.command(name="load")
@click.option(
    "--passphrase/--no-passphrase",
    default=False,
    help="Prompt for the BIP39 passphrase used at wallet creation.",
)
@click.pass_obj
def wallet_load(ctx: CliContext, passphrase: bool) -> None:
    """Validate that an existing wallet decrypts.

    Prompts for the mnemonic (input hidden via getpass). Does not modify
    the wallet file.
    """
    if not ctx.wallet_path.exists():
        raise UserError(
            f"no wallet at {ctx.wallet_path}",
            cause="the file does not exist",
            fix="run `pyrxd wallet new` to create one, or pass --wallet PATH to point at a different file",
        )

    mnemonic = prompt_mnemonic_input()
    if not mnemonic:
        raise UserError(
            "mnemonic is required",
            cause="no input received",
            fix="enter the BIP39 mnemonic the wallet was created with",
        )

    passphrase_str = ""  # nosec B105 — empty string is the BIP39 spec default, not a hardcoded secret
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=False)

    try:
        wallet = HdWallet.load(ctx.wallet_path, mnemonic, passphrase_str)
    except (ValidationError, ValueError) as exc:
        # ValidationError: the library's static "Could not decrypt" message.
        # ValueError:      bip39.validate_mnemonic raises ValueError when
        #                  a word isn't in the wordlist. Both surface to
        #                  the user as exit code 3 with the same static
        #                  message — we never echo the user's input.
        raise WalletDecryptError() from exc

    payload = {
        "wallet_path": str(ctx.wallet_path),
        "account": wallet.account,
        "external_tip": wallet.external_tip,
        "internal_tip": wallet.internal_tip,
        "addresses_known": len(wallet.addresses),
    }
    if ctx.output_mode == "human":
        lines = [
            f"Wallet at {ctx.wallet_path} decrypts successfully.",
            f"  account: {wallet.account}",
            f"  external tip: {wallet.external_tip}",
            f"  internal tip: {wallet.internal_tip}",
            f"  known addresses: {len(wallet.addresses)}",
        ]
        click.echo(emit(payload, mode="human", human_lines=lines))
    elif ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    else:  # quiet
        click.echo(emit(payload, mode="quiet", quiet_field="account"))


@wallet_group.command(name="export-xpub")
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def wallet_export_xpub(ctx: CliContext, passphrase: bool) -> None:
    """Print the account-level xpub for watch-only / recipient use.

    The xpub at ``m/44'/<coin_type>'/<account>'`` lets external tools generate
    receive addresses for this wallet without ever seeing the seed.
    Safe to share with watch-only services or merchant integrations.
    No private key material is exported.
    """
    if not ctx.wallet_path.exists():
        raise UserError(
            f"no wallet at {ctx.wallet_path}",
            cause="the file does not exist",
            fix="run `pyrxd wallet new` to create one, or pass --wallet PATH",
        )
    mnemonic = prompt_mnemonic_input()
    if not mnemonic:
        raise UserError("mnemonic is required")

    passphrase_str = ""  # nosec B105 — empty string is the BIP39 spec default
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=False)

    try:
        wallet = HdWallet.load(ctx.wallet_path, mnemonic, passphrase_str)
    except (ValidationError, ValueError) as exc:
        raise WalletDecryptError() from exc

    xpub = wallet._xprv.xpub()
    payload = {
        "xpub": str(xpub),
        "account": wallet.account,
        "path": f"m/44'/{wallet.coin_type}'/{wallet.account}'",
    }
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="xpub"))
    else:
        click.echo(f"\nxpub at m/44'/{wallet.coin_type}'/{wallet.account}':")
        click.echo(f"  {xpub}")
        click.echo("\nThis xpub lets external tools generate receive addresses")
        click.echo("for this wallet WITHOUT seeing the seed. Safe to share with")
        click.echo("watch-only services. Do NOT share the mnemonic.")


@wallet_group.command(name="info")
@click.option(
    "--passphrase/--no-passphrase",
    default=False,
    help="Prompt for the BIP39 passphrase if the wallet was created with one.",
)
@click.pass_obj
def wallet_info(ctx: CliContext, passphrase: bool) -> None:
    """Print local-only wallet stats. No network calls."""
    # `wallet info` and `wallet load` overlap — info is a friendly alias
    # of load for the common "is this wallet OK?" check. Same flow.
    ctx_obj = click.get_current_context()
    ctx_obj.invoke(wallet_load, passphrase=passphrase)


@wallet_group.command(name="recover")
@click.option(
    "--scan",
    is_flag=True,
    default=False,
    help="Scan multiple BIP44 paths for on-chain history (required; reserved for future modes).",
)
@click.option(
    "--coin-types",
    default=",".join(str(c) for c in DEFAULT_COIN_TYPES),
    show_default=True,
    help="Comma-separated SLIP-0044 coin types to scan (0=legacy/Photonic≤v2/Chainbow, 512=SLIP-0044, 236=old pyrxd).",
)
@click.option(
    "--accounts",
    default=",".join(str(a) for a in DEFAULT_ACCOUNTS),
    show_default=True,
    help="Comma-separated BIP44 account indices to scan.",
)
@click.option(
    "--passphrase/--no-passphrase",
    default=False,
    help="Prompt for the BIP39 passphrase if the seed was created with one.",
)
@click.pass_obj
def wallet_recover(ctx: CliContext, scan: bool, coin_types: str, accounts: str, passphrase: bool) -> None:
    """Find funds across BIP44 derivation paths for a mnemonic (read-only).

    Different Radiant wallets (Photonic, Chainbow, Electron, Tangem) and even
    different versions of the same wallet derive different addresses from one
    seed, so a balance can be visible on the explorer yet invisible in a wallet
    that derives the wrong path. This scans every ``coin_type × account`` pair
    over both BIP44 chains and reports which derived addresses hold funds.

    Read-only: it never signs or broadcasts. Once it reports a path, sweep with
    your own wallet, or a separate explicit send.
    """
    if not scan:
        raise UserError(
            "recover currently supports only --scan mode",
            cause="the flag was omitted",
            fix="run `pyrxd wallet recover --scan`",
        )

    coin_type_list = _parse_int_csv(coin_types, flag="--coin-types")
    account_list = _parse_int_csv(accounts, flag="--accounts")

    mnemonic = prompt_mnemonic_input()
    if not mnemonic:
        raise UserError(
            "mnemonic is required",
            cause="no input received",
            fix="enter the BIP39 mnemonic to recover",
        )
    passphrase_str = ""  # nosec B105 — empty string is the BIP39 spec default, not a hardcoded secret
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=False)

    # Validate the mnemonic up front so an obvious typo fails fast with a
    # clean message instead of mid-scan. We never echo the user's input.
    try:
        HdWallet.from_mnemonic(mnemonic, passphrase=passphrase_str, coin_type=coin_type_list[0])
    except (ValidationError, ValueError) as exc:
        raise WalletDecryptError() from exc

    async def _scan() -> object:
        client = ctx.make_client()
        async with client:
            return await discover(
                client,
                mnemonic,
                passphrase=passphrase_str,
                coin_types=coin_type_list,
                accounts=account_list,
            )

    try:
        report = asyncio.run(_scan())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX during recovery scan",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable, or use --electrumx URL",
        ) from exc

    payload = {
        "network": ctx.network,
        "found": report.found,  # type: ignore[attr-defined]
        "total_confirmed_photons": report.total_confirmed,  # type: ignore[attr-defined]
        "total_unconfirmed_photons": report.total_unconfirmed,  # type: ignore[attr-defined]
        "scanned": [list(pair) for pair in report.scanned],  # type: ignore[attr-defined]
        "hits": [
            {
                "path": h.path,
                "coin_type": h.coin_type,
                "coin_type_label": coin_type_label(h.coin_type),
                "account": h.account,
                "change": h.change,
                "index": h.index,
                "address": h.address,
                "confirmed_photons": h.confirmed,
                "unconfirmed_photons": h.unconfirmed,
            }
            for h in report.hits  # type: ignore[attr-defined]
        ],
    }

    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
        return
    if ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="total_confirmed_photons"))
        return

    if not report.found:  # type: ignore[attr-defined]
        scanned_desc = ", ".join(f"coin {c}/acct {a}" for c, a in report.scanned)  # type: ignore[attr-defined]
        lines = [
            "No on-chain history found at any scanned path.",
            f"  scanned: {scanned_desc}",
            "",
            "Next steps:",
            "  - widen the search: --coin-types 0,512,236 --accounts 0,1,2,3",
            "  - confirm the funded address on an explorer and check it matches one of these paths",
            "  - double-check the mnemonic words and order",
        ]
        click.echo(emit(payload, mode="human", human_lines=lines))
        return

    lines = ["Found funds. Recover with the wallet that derives the matching path:", ""]
    for h in report.hits:  # type: ignore[attr-defined]
        # Show the TOTAL (confirmed + pending), not just confirmed — recovered
        # or just-received funds are often still unconfirmed, and showing only
        # h.confirmed would print "0" next to a path that actually holds money.
        if h.total == 0:
            amount = f"{format_photons(0)}  (history only — 0 balance)"
        elif h.confirmed == 0:
            amount = f"{format_photons(h.unconfirmed)}  (pending)"
        elif h.unconfirmed:
            amount = f"{format_photons(h.total)}  (incl. {format_photons(h.unconfirmed)} pending)"
        else:
            amount = format_photons(h.confirmed)
        lines.append(f"  {amount}  {h.path}")
        lines.append(f"      coin type {h.coin_type} — {coin_type_label(h.coin_type)}")
        lines.append(f"      {h.address}")
    lines.append("")
    lines.append(f"Total confirmed   {format_photons(report.total_confirmed)}")  # type: ignore[attr-defined]
    if report.total_unconfirmed:  # type: ignore[attr-defined]
        lines.append(f"Total pending     {format_photons(report.total_unconfirmed)}")  # type: ignore[attr-defined]
    click.echo(emit(payload, mode="human", human_lines=lines))


@wallet_group.command(name="sweep")
@click.option(
    "--coin-type",
    type=int,
    required=True,
    help="SLIP-0044 coin type the funds are on (e.g. 0 or 512). Use `wallet recover --scan` to find it.",
)
@click.option(
    "--account",
    type=int,
    default=0,
    show_default=True,
    help="BIP44 account index the funds are on.",
)
@click.option(
    "--to",
    "to_address",
    required=True,
    help="Destination address to send everything to (an address you control).",
)
@click.option(
    "--fee-rate",
    type=int,
    default=DEFAULT_FEE_RATE,
    show_default=True,
    help="Fee rate in photons per kB.",
)
@click.option(
    "--passphrase/--no-passphrase",
    default=False,
    help="Prompt for the BIP39 passphrase if the seed was created with one.",
)
@click.pass_obj
def wallet_sweep(
    ctx: CliContext, coin_type: int, account: int, to_address: str, fee_rate: int, passphrase: bool
) -> None:
    """Move ALL funds from a derived path to an address you control.

    Sweeps every spendable UTXO under ``m/44'/<coin-type>'/<account>'`` to --to,
    minus the network fee. Use this to rescue funds that `wallet recover --scan`
    found at a derivation path no GUI wallet can reach (a non-zero account, or a
    higher address index).

    This signs and broadcasts a real transaction. You are shown the amount,
    fee, and destination, and asked to confirm before anything is broadcast.
    """
    if coin_type < 0 or account < 0:
        raise UserError("--coin-type and --account must be non-negative")
    if fee_rate <= 0:
        # Validate before the mnemonic prompt so a bad invocation fails
        # without the user first typing their seed.
        raise UserError("--fee-rate must be a positive integer (photons per kB)")
    # Block --json without --yes early (a broadcast must not auto-confirm).
    ok, why = ctx.is_destructive_mode_safe()
    if not ok:
        raise UserError(why or "destructive op without --yes in --json mode")
    # Pin the destination to the ACTIVE network. Without this, a testnet-prefixed
    # address (m.../n...) passes validation on mainnet, and the sweep pays a
    # script no mainnet key can spend — an unrecoverable loss from a paste error.
    if not validate_address(to_address, network=Network(ctx.network)):
        raise UserError(
            "invalid --to address",
            cause=f"not a valid {ctx.network} Radiant P2PKH address",
            fix=f"pass a {ctx.network} address you control" + (" (starts with 1)" if ctx.network == "mainnet" else ""),
        )

    mnemonic = prompt_mnemonic_input()
    if not mnemonic:
        raise UserError(
            "mnemonic is required",
            cause="no input received",
            fix="enter the BIP39 mnemonic for the wallet holding the funds",
        )
    passphrase_str = ""  # nosec B105 — empty string is the BIP39 spec default, not a hardcoded secret
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=False)

    try:
        wallet = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase_str, account=account, coin_type=coin_type)
    except (ValidationError, ValueError) as exc:
        raise WalletDecryptError() from exc

    path = f"m/44'/{coin_type}'/{account}'"

    async def _sweep() -> dict[str, object]:
        client = ctx.make_client()
        async with client:
            await wallet.refresh(client)
            triples = await wallet.collect_spendable(client)
            if not triples:
                raise UserError(
                    f"no spendable funds at {path}",
                    cause="the scan found no UTXOs on this coin type / account",
                    fix="double-check --coin-type and --account (run `wallet recover --scan` first)",
                )
            tx = wallet.build_send_max_tx(triples, to_address, fee_rate=fee_rate)
            total_in = sum(t[0].value for t in triples)
            out_value = tx.outputs[0].satoshis
            fee = total_in - out_value

            summary = [
                "\n  Sweep:",
                f"    from path:   {path} ({coin_type_label(coin_type)})",
                f"    inputs:      {len(triples)} UTXO(s)",
                f"    total found: {format_photons(total_in)}",
                f"    network fee: {format_photons(fee)}",
                f"    you receive: {format_photons(out_value)}",
                f"    to address:  {to_address}",
                "",
            ]
            if not confirm_action(summary, ctx=ctx, prompt_text="Broadcast this sweep?"):
                raise UserError(
                    "aborted by user",
                    cause="confirmation declined",
                    fix="re-run when you are ready to broadcast",
                )

            txid = await client.broadcast(tx.serialize())
            return {
                "txid": str(txid),
                "from_path": path,
                "to": to_address,
                "swept_photons": out_value,
                "fee_photons": fee,
                "inputs": len(triples),
            }

    try:
        result = asyncio.run(_sweep())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable, or use --electrumx URL",
        ) from exc
    except ValidationError as exc:
        # build_send_max_tx raises ValidationError when the balance is at or
        # below the network fee (dust). Lead with the honest framing — these
        # coins are simply too small to move; lowering --fee-rate only helps if
        # the user raised it above the default in the first place.
        raise UserError(
            "could not build the sweep transaction",
            cause=str(exc),
            fix="this balance is too small to move — it does not exceed the network fee (dust). "
            "Lower --fee-rate only if you raised it above the default; otherwise these coins cannot be swept.",
        ) from exc

    if ctx.output_mode == "json":
        click.echo(emit(result, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(result, mode="quiet", quiet_field="txid"))
    else:
        click.echo(f"\nSwept {format_photons(cast(int, result['swept_photons']))} to {to_address}")
        click.echo(f"Transaction: {result['txid']}")


# Confirmation helper used by Cut 1 destructive ops outside this module.
# Re-exported for tests + future cuts.
__all__ = [
    "wallet_export_xpub",
    "wallet_group",
    "wallet_info",
    "wallet_load",
    "wallet_new",
    "wallet_recover",
    "wallet_sweep",
]
