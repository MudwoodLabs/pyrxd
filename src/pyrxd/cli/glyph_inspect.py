"""``pyrxd glyph inspect`` — read-only classifier for Glyph inputs.

Extracted from :mod:`pyrxd.cli.glyph_cmds` so the single largest, most
self-contained feature in that module stands on its own. ``inspect`` is
read-only by design (no wallet load, no broadcast, no mnemonic prompt):
it classifies a txid / contract id / outpoint / hex locking script and
renders the result in json / quiet / human modes.

The pure classifiers and threat-model constants live one layer down in
:mod:`pyrxd.glyph._inspect_core` so the browser-hosted inspect tool
(loaded into Pyodide) can import them without dragging in the CLI's
``click`` / wallet / network dependencies. The thin wrappers here
translate the SDK-level :class:`~pyrxd.security.errors.ValidationError`
into the CLI-shaped :class:`~pyrxd.cli.errors.UserError` with the
cause/fix decorations the formatter expects.

The command object is built with a bare ``@click.command`` and attached
to the ``glyph`` group by :mod:`pyrxd.cli.glyph_cmds` via
``glyph_group.add_command(inspect_cmd)`` — the canonical Click pattern
for splitting a group's subcommands across modules.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import click

from ..glyph._inspect_core import _HUMAN_STRING_CAP as _HUMAN_STRING_CAP
from ..glyph._inspect_core import _classify_input as _classify_input_core
from ..glyph._inspect_core import _classify_raw_tx as _classify_raw_tx_core
from ..glyph._inspect_core import _inspect_contract as _inspect_contract_core
from ..glyph._inspect_core import _inspect_outpoint as _inspect_outpoint_core
from ..glyph._inspect_core import _inspect_script as _inspect_script_core
from ..glyph._inspect_core import _sanitize_display_string as _sanitize_display_string
from ..glyph._inspect_core import _truncate_for_human
from ..security.errors import NetworkError, ValidationError
from ..security.types import Txid
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient

__all__ = [
    "inspect_cmd",
]


# Input forms recognised by `glyph inspect`. Each is unambiguous by shape:
#   txid       — exactly 64 lowercase-hex chars
#   contract   — exactly 72 lowercase-hex chars (txid + BE vout)
#   outpoint   — anything containing ":"
#   script     — any other hex string of even length (>= 50 chars / 25 bytes)
# Everything else is a UserError.


def _classify_input(s: str) -> tuple[str, str]:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``."""
    try:
        return _classify_input_core(s)
    except ValidationError as exc:
        msg = str(exc)
        if msg == "inspect input is empty":
            raise UserError(msg) from exc
        # The "could not classify" case carries the input length in the
        # message; the original CLI exposed that plus a cause/fix pair.
        raise UserError(
            msg,
            cause="input is not a 64-char txid, 72-char contract id, txid:vout outpoint, or 50-20000 char hex script",
            fix="paste a 64-char txid (with --fetch), 72-char contract id, txid:vout, or hex script",
        ) from exc


def _inspect_contract(contract_hex: str) -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``."""
    try:
        return _inspect_contract_core(contract_hex)
    except ValidationError as exc:
        raise UserError("contract id failed to parse", cause=str(exc)) from exc


def _inspect_outpoint(s: str) -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``.

    The shape errors carried by ``_inspect_outpoint_core`` are
    self-contained (e.g. ``"vout is not an integer"``); parser errors
    from downstream get the historic ``"outpoint failed to parse"``
    prefix so existing CLI test assertions match unchanged."""
    try:
        return _inspect_outpoint_core(s)
    except ValidationError as exc:
        msg = str(exc)
        if msg.startswith("outpoint must be") or msg.startswith("vout is not an integer"):
            raise UserError(msg) from exc
        raise UserError("outpoint failed to parse", cause=msg) from exc


def _inspect_script(script_hex: str) -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError``."""
    try:
        return _inspect_script_core(script_hex)
    except ValidationError as exc:
        raise UserError(str(exc)) from exc


def _classify_raw_tx(txid_hex: str, raw: bytes, *, only_vout: int | None = None) -> dict:
    """CLI wrapper: translate ``ValidationError`` to ``UserError`` with
    the historic CLI-formatted cause/fix decorations.

    The core raises a flat ``ValidationError`` whose message embeds the
    relevant detail. Pattern-match on the message to reconstruct the
    CLI's three-line ``error / cause / fix`` formatting so existing
    test assertions (e.g. on ``"--electrumx"``) keep matching."""
    try:
        return _classify_raw_tx_core(txid_hex, raw, only_vout=only_vout)
    except ValidationError as exc:
        msg = str(exc)
        if "raw bytes too short" in msg:
            raise UserError(
                "raw bytes too short for a valid transaction",
                cause=f"got {len(raw)} bytes; need >64",
                fix="confirm the source returned a real transaction, not a header or stub",
            ) from exc
        if "transaction is larger than the policy max" in msg:
            from ..glyph._inspect_core import _MAX_RAW_TX_BYTES

            raise UserError(
                "transaction is larger than the policy max",
                cause=f"server returned {len(raw)} bytes; policy max is {_MAX_RAW_TX_BYTES}",
                fix="confirm the txid; a tx this large is consensus-invalid",
            ) from exc
        if "does not match the requested txid" in msg:
            cause = msg.split("(", 1)[1].rstrip(")") if "(" in msg else msg
            raise UserError(
                "server returned a transaction whose hash does not match the requested txid",
                cause=cause,
                fix="try a different ElectrumX server (--electrumx URL)",
            ) from exc
        if msg == "could not parse the raw transaction bytes":
            raise UserError(
                "could not parse the raw transaction bytes",
                cause="Transaction.from_hex returned None",
                fix="the server response is malformed; try another ElectrumX server",
            ) from exc
        if "exceeds inspect's safety caps" in msg:
            from ..glyph._inspect_core import _MAX_INPUT_COUNT, _MAX_OUTPUT_COUNT

            cause = msg.split("(", 1)[1].rstrip(")") if "(" in msg else msg
            raise UserError(
                "transaction structure exceeds inspect's safety caps",
                cause=cause,
                fix=f"caps are {_MAX_INPUT_COUNT}/{_MAX_OUTPUT_COUNT} — re-run on a saner tx",
            ) from exc
        if "out of range" in msg:
            head = msg.split("(", 1)[0].strip()
            cause = msg.split("(", 1)[1].rstrip(")") if "(" in msg else ""
            raise UserError(head, cause=cause) from exc
        if msg.startswith("invalid txid") or "Txid" in msg or "must be 64-char" in msg:
            raise UserError("invalid txid", cause=msg) from exc
        # Fallthrough: surface unexpected ValidationError as a bare
        # UserError so the CLI stays deterministic.
        raise UserError(msg) from exc


async def _inspect_txid_inner(client: ElectrumXClient, txid_hex: str, *, only_vout: int | None = None) -> dict:
    """Fetch *txid_hex* via *client* and classify every output.

    Thin async wrapper around :func:`_classify_raw_tx`. The split is so
    the browser-hosted inspect tool can fetch raw bytes via its own
    WebSocket and feed them directly into the synchronous classifier
    without setting up an event loop or an ``ElectrumXClient`` under
    Pyodide.

    :param only_vout: if not None, restrict the outputs list to a single
        vout — used by the ``--resolve`` outpoint flow.
    """
    # Validate the txid locally before any network call so a malformed
    # input never reaches the server.
    try:
        txid = Txid(txid_hex.lower())
    except ValidationError as exc:
        raise UserError("invalid txid", cause=str(exc)) from exc

    raw = await client.get_transaction(txid)
    return _classify_raw_tx(str(txid), bytes(raw), only_vout=only_vout)


def _render_txid_human(payload: dict) -> str:
    """Format a fetched-tx inspect result for human mode."""
    lines = [
        f"Transaction: {payload['txid']}",
        f"  size:    {payload['byte_length']} bytes",
        f"  inputs:  {payload['input_count']}",
        f"  outputs: {payload['output_count']}",
        "",
    ]
    rows = payload.get("outputs") or []
    if not rows:
        lines.append("  (no outputs)")
    else:
        lines.append("Outputs:")
        for row in rows:
            sats = row.get("satoshis", "?")
            type_ = row.get("type", "?")
            head = f"  vout {row['vout']:>3}  type={type_:<10}  sats={sats}"
            lines.append(head)
            if type_ in ("nft", "ft"):
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ == "mut":
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            payload_hash={row.get('payload_hash', '')}")
            elif type_ in ("commit-nft", "commit-ft"):
                lines.append(f"            payload_hash={row.get('payload_hash', '')}")
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ == "dmint":
                lines.append(f"            contract_ref={row.get('contract_ref_outpoint', '')}")
                lines.append(f"            token_ref={row.get('token_ref_outpoint', '')}")
                lines.append(
                    f"            height={row.get('height')}/{row.get('max_height')} "
                    f"reward={row.get('reward')} algo={row.get('algo')}"
                )
            elif type_ == "p2pkh":
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ == "error":
                lines.append(f"            (classifier error: {row.get('error')})")
    metadata = payload.get("metadata")
    if metadata is not None:
        lines.append("")
        lines.append(f"Reveal metadata (from input {metadata['input_index']}):")
        lines.append(f"  protocol: {metadata['protocol']}")
        if metadata.get("name"):
            lines.append(f"  name:     {_truncate_for_human(metadata['name'])}")
        if metadata.get("ticker"):
            lines.append(f"  ticker:   {_truncate_for_human(metadata['ticker'])}")
        if metadata.get("description"):
            lines.append(f"  desc:     {_truncate_for_human(metadata['description'])}")
        if metadata.get("decimals"):
            lines.append(f"  decimals: {metadata['decimals']}")
        if metadata.get("main"):
            lines.append(f"  main:     {metadata['main']}")
    # dMint mint-claim scriptSig (vin[0] only). 4 canonical pushes:
    # nonce, SHA256d(funding_script), SHA256d(OP_RETURN_script), OP_0.
    # V1 = 4-byte nonce / 72-byte scriptSig; V2 = 8-byte / 76-byte.
    mint_scriptsig = payload.get("mint_scriptsig")
    if mint_scriptsig is not None:
        lines.append("")
        lines.append("dMint mint scriptSig (vin 0):")
        lines.append(f"  version (by nonce width): {mint_scriptsig.get('version_hint', '?')}")
        lines.append(f"  scriptSig length:         {mint_scriptsig.get('scriptsig_length')} bytes")
        lines.append(f"  nonce (LE):               {mint_scriptsig.get('nonce_hex')}")
        lines.append(f"  input  hash (SHA256d):    {mint_scriptsig.get('input_hash')}")
        lines.append(f"  output hash (SHA256d):    {mint_scriptsig.get('output_hash')}")
        lines.append("  (input  hash = SHA256d of the funding-input locking script;")
        lines.append("   output hash = SHA256d of the OP_RETURN message script at vout[2];")
        lines.append("   these are literal SHA256d pushes, not preimage halves —")
        lines.append("   the covenant recomputes SHA256(input_hash || output_hash))")
    return "\n".join(lines)


def _render_inspect_human(payload: dict) -> str:
    """Format a single inspect result for the human output mode."""
    form = payload.get("form", "?")
    if form == "script":
        return _render_script_human(payload)
    if form == "txid":
        return _render_txid_human(payload)
    if form == "contract":
        lines = [
            "Contract id (explorer display form):",
            f"  txid:     {payload['txid']}",
            f"  vout:     {payload['vout']}",
            f"  outpoint: {payload['outpoint']}",
            "",
            f"Wire form (inside scripts): {payload['wire_hex']}",
        ]
        return "\n".join(lines)
    if form == "outpoint":
        lines = [
            "Outpoint:",
            f"  txid:     {payload['txid']}",
            f"  vout:     {payload['vout']}",
            f"  outpoint: {payload['outpoint']}",
            "",
            f"Wire form (inside scripts): {payload['wire_hex']}",
        ]
        return "\n".join(lines)
    return "\n".join(f"{k}: {v}" for k, v in payload.items())


def _render_script_human(payload: dict) -> str:
    """Pretty-print a classified script result."""
    type_ = payload.get("type", "?")
    head = f"type: {type_}    length: {payload['length']} bytes"
    body: list[str] = []
    if type_ == "p2pkh":
        body.append(f"  owner_pkh: {payload['owner_pkh']}")
    elif type_ in ("nft", "ft"):
        body.append(f"  ref:       {payload['ref_outpoint']}")
        body.append(f"  owner_pkh: {payload['owner_pkh']}")
        body.append("  (structural pattern match: bytes match the FT/NFT script template;")
        body.append("   does NOT verify the ref points to a valid Glyph contract)")
    elif type_ == "mut":
        body.append(f"  ref:          {payload['ref_outpoint']}")
        body.append(f"  payload_hash: {payload['payload_hash']}")
        body.append("  (structural pattern match; payload_hash is an opaque commitment")
        body.append("   to off-chain CBOR — resolve via the reveal tx; `inspect` cannot")
        body.append("   verify provenance of the ref locally)")
    elif type_ in ("commit-nft", "commit-ft"):
        body.append(f"  payload_hash: {payload['payload_hash']}")
        body.append(f"  owner_pkh:    {payload['owner_pkh']}")
        body.append("  (structural pattern match; payload_hash is an opaque commitment")
        body.append("   to the reveal-tx CBOR)")
    elif type_ == "dmint":
        version = payload.get("version", "?")
        body.append(f"  version:      dMint {version}")
        body.append(f"  contract_ref: {payload['contract_ref_outpoint']}")
        body.append(f"  token_ref:    {payload['token_ref_outpoint']}")
        body.append(f"  height:       {payload['height']} / {payload['max_height']}")
        body.append(f"  reward:       {payload['reward']} photons/mint")
        # Total minted supply if all mints succeed.
        total = payload["max_height"] * payload["reward"]
        body.append(f"  total supply: {total:,} photons")
        body.append(f"  algo:         {payload['algo']}")
        body.append(f"  daa_mode:     {payload['daa_mode']}")
        body.append("  (structural pattern match; does NOT verify the contract_ref points")
        body.append("   to a valid mint chain or that the parameters match a deployed token)")
    elif type_ == "unknown":
        body.append("  (script does not match any known Glyph or P2PKH layout)")
    return "\n".join([head, *body])


@click.command(name="inspect")
@click.argument("inspect_input", metavar="INPUT")
@click.option(
    "--fetch",
    "fetch",
    is_flag=True,
    default=False,
    help="Fetch the transaction from ElectrumX. Required for txid input.",
)
@click.option(
    "--resolve",
    "resolve",
    is_flag=True,
    default=False,
    help="For an outpoint, fetch its source tx and classify the named vout.",
)
@click.pass_obj
def inspect_cmd(ctx: CliContext, inspect_input: str, fetch: bool, resolve: bool) -> None:
    """Classify a Glyph input.

    INPUT can be:

    \b
      • a 64-char txid              (requires --fetch)
      • a 72-char contract id       (e.g. "b45dc4...a2a800000004")
      • an outpoint "txid:vout"     (add --resolve to fetch its source tx)
      • a hex-encoded locking script (P2PKH / FT / NFT / mut / commit / dmint)

    Pass --json for machine output (auto-detects when stdout is piped). Read-
    only by design — no broadcast, no wallet load, no mnemonic prompt.

    \b
    --json response schema (stable; new fields may be added without notice):
      contract  → {form, txid, vout, outpoint, wire_hex}
      outpoint  → {form, txid, vout, outpoint, wire_hex}
      script    → {form, length, hex, type, ...type-specific fields}
        type=p2pkh        → owner_pkh
        type=nft / ft     → ref_txid, ref_vout, ref_outpoint, owner_pkh
        type=mut          → ref_txid, ref_vout, ref_outpoint, payload_hash
        type=commit-nft / commit-ft → payload_hash, owner_pkh
        type=dmint        → version (v1|v2), contract_ref_outpoint,
                            token_ref_outpoint, height, max_height, reward,
                            algo, daa_mode
        type=unknown      → (no extra fields)
      txid (--fetch)   → {form, txid, byte_length, input_count, output_count,
                          outputs[], metadata, mint_scriptsig}
        outputs[]: {vout, type, satoshis, ...same per-type fields as script form}
        mint_scriptsig: null OR {nonce_hex, input_hash, output_hash,
                          version_hint ("v1"|"v2"), scriptsig_length} —
                          present when vin[0] is a dMint V1/V2 mint claim

    All hex values are lowercase. Outpoints render as "txid:vout"
    (display order). Wire forms (txid reversed + vout LE) appear under
    ``wire_hex`` for contract/outpoint forms.

    Network defaults (fetch path): connects to the configured ElectrumX URL
    (override with the top-level --electrumx flag). TLS is enforced; raw
    ws:// is rejected by the underlying client. Default timeout: 30s. Server
    responses are bound-checked (size cap, input/output count caps) and the
    returned tx is verified against the requested txid by sha256d roundtrip.
    """
    form, value = _classify_input(inspect_input)

    # Forms that need a network fetch.
    needs_fetch = (form == "txid") or (form == "outpoint" and resolve)

    if form == "txid" and not fetch:
        raise UserError(
            "txid inspection requires --fetch",
            cause="this looks like a txid (64 hex chars)",
            fix="re-run with --fetch to query ElectrumX for the transaction",
        )
    if fetch and form not in ("txid",):
        raise UserError(
            "--fetch is only meaningful for txid input",
            fix="use --resolve to fetch an outpoint's source tx",
        )
    if resolve and form != "outpoint":
        raise UserError(
            "--resolve is only meaningful for an outpoint input",
        )

    if needs_fetch:
        payload = _run_fetch_inspect(ctx, form=form, value=value)
    elif form == "contract":
        payload = _inspect_contract(value)
    elif form == "outpoint":
        payload = _inspect_outpoint(value)
    elif form == "script":
        payload = _inspect_script(value)
    else:  # pragma: no cover — _classify_input never returns other values
        raise UserError(f"internal: unknown form {form!r}")

    mode = ctx.output_mode
    if mode == "json":
        click.echo(emit(payload, mode="json"))
    elif mode == "quiet":
        # Pick the single most-useful string per form.
        if form == "script":
            click.echo(payload.get("type", ""))
        elif form == "txid":
            click.echo(payload.get("txid", ""))
        else:
            click.echo(payload.get("outpoint", ""))
    else:
        click.echo(_render_inspect_human(payload))


def _run_fetch_inspect(ctx: CliContext, *, form: str, value: str) -> dict:
    """Spin up an ElectrumX client, run _inspect_txid_inner, surface errors.

    Wraps NetworkError → NetworkBoundaryError (exit code 2) so a
    user can distinguish "wrong input" (UserError, exit 1) from
    "network is down" (exit 2).
    """

    async def _do() -> dict:
        client = ctx.make_client()
        async with client:
            if form == "txid":
                return await _inspect_txid_inner(client, value)
            # form == "outpoint" + resolve: parse, fetch the source, classify
            # only the named vout.
            outpoint_payload = _inspect_outpoint(value)
            return await _inspect_txid_inner(
                client,
                outpoint_payload["txid"],
                only_vout=outpoint_payload["vout"],
            )

    try:
        return asyncio.run(_do())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable",
        ) from exc
