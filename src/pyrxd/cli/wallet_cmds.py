"""``pyrxd wallet …`` subcommand group.

Cut 1 commands:
  wallet new       Generate a fresh BIP39 mnemonic + HdWallet.
  wallet load      Validate that an existing wallet decrypts.
  wallet info      Show local-only wallet stats (no network).

Cut 3 (deferred):
  wallet export-xpub  Print account xpub for watch-only use.
"""

from __future__ import annotations

import click

from ..hd.bip39 import mnemonic_from_entropy
from ..hd.wallet import HdWallet
from ..security.errors import ValidationError
from ..security.rng import secure_random_bytes
from .context import CliContext
from .errors import UserError, WalletDecryptError
from .format import emit
from .main import cli
from .prompts import (
    prompt_mnemonic_input,
    prompt_passphrase_input,
    show_mnemonic,
)


@cli.group(name="wallet")
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
@click.pass_obj
def wallet_new(ctx: CliContext, mnemonic_words: str, passphrase: bool) -> None:
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

    # In JSON mode: emit the mnemonic as JSON without the gate. The user
    # passed --yes deliberately, so we trust them. In any other mode,
    # show the box + Enter gate.
    if ctx.output_mode == "json":
        passphrase_str = ""
        if passphrase:
            passphrase_str = prompt_passphrase_input(optional=True)
        wallet = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase_str)
        wallet.save(ctx.wallet_path)
        click.echo(
            emit(
                {
                    "mnemonic": mnemonic,
                    "wallet_path": str(ctx.wallet_path),
                    "address": wallet.next_receive_address(),
                },
                mode="json",
            )
        )
        return

    show_mnemonic(mnemonic.split(), ctx=ctx)
    passphrase_str = ""
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=True)
    wallet = HdWallet.from_mnemonic(mnemonic, passphrase=passphrase_str)
    wallet.save(ctx.wallet_path)
    next_addr = wallet.next_receive_address()

    if ctx.output_mode == "quiet":
        click.echo(emit({"address": next_addr}, mode="quiet", quiet_field="address"))
        return

    click.echo("")
    click.echo(f"Wallet saved to {ctx.wallet_path}")
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

    passphrase_str = ""
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=False)

    try:
        wallet = HdWallet.load(ctx.wallet_path, mnemonic, passphrase_str)
    except ValidationError as exc:
        # Library raises a single static "Could not decrypt" message.
        # Surface that to the user under exit code 3.
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


# Confirmation helper used by Cut 1 destructive ops outside this module.
# Re-exported for tests + future cuts.
__all__ = ["wallet_group", "wallet_info", "wallet_load", "wallet_new"]
