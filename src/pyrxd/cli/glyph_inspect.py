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
from ..script.timelock import LOCKTIME_THRESHOLD
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
#   script     — any other hex string of even length (>= 46 chars / 23 bytes)
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
            cause="input is not a 64-char txid, 72-char contract id, txid:vout outpoint, or 46-20000 char hex script",
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
            # An OP_RETURN payload's verdict must reach the terminal HERE too, not
            # only in the pasted-script view. This is the path that reaches a record
            # actually on chain, and without it a v2 whose signature DOES NOT VERIFY
            # rendered identically to a genuine one.
            lines.extend(_op_return_payload_lines(row, indent="            "))
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
            elif type_ == "container-legacy":
                lines.append(f"            ref={row.get('ref_outpoint', '')}")
                lines.append(f"            child_ref={row.get('child_ref_outpoint', '')}")
                lines.append("            UNSPENDABLE — see `pyrxd glyph inspect <script>` for why")
            elif type_ == "p2pkh":
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
            elif type_ == "p2sh":
                lines.append(f"            script_hash={row.get('script_hash', '')}")
            elif type_ in ("p2pkh-cltv", "p2pkh-csv"):
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
                lines.append(
                    f"            lock={row.get('locktime_units')} {row.get('locktime_basis')}"
                    + ("  *** DISABLED ***" if row.get("relative_lock_disabled") else "")
                )
            elif type_ == "soulbound-covenant":
                lines.append(f"            bound_ref={row.get('bound_ref_outpoint', '')}")
                lines.append(f"            owner_pkh={row.get('owner_pkh', '')}")
                lines.append(f"            variant={row.get('variant', '')} (non-transferable at consensus)")
            elif type_ == "self-replicating-covenant":
                lines.append(f"            bound_ref={row.get('bound_ref_outpoint', '(multiple)')}")
                lines.append("            markers only — NOT proof of soulbound")
            elif type_ == "unknown":
                # Carried (0xd0/0xd8) vs merely named (0xd1/0xd2/0xd3). Only the
                # first burns when this output is spent as plain funding.
                for ref_row in row.get("input_refs") or []:
                    lines.append(f"            ref={ref_row['ref_outpoint']} ({ref_row['opcode']}) TOKEN-BEARING")
                for ref_row in row.get("referenced_refs") or []:
                    lines.append(
                        f"            ref={ref_row['ref_outpoint']} ({ref_row['opcode']}) referenced, not carried"
                    )
                if row.get("token_bearing") is None:
                    lines.append("            token-bearing UNKNOWN (does not decode) — treat as token-bearing")
            elif type_ == "error":
                lines.append(f"            (classifier error: {row.get('error')})")
    metadata = payload.get("metadata")
    if metadata is not None:
        lines.append("")
        # SAY WHEN IT IS ONE OF SEVERAL (#577). A multi-glyph reveal carries a
        # payload per minted glyph; printing one under a bare "Reveal metadata"
        # heading told the reader it described the transaction. One observed
        # mainnet reveal mints 35 refs from 36 inputs.
        n_payloads = metadata.get("of_n_payloads")
        if n_payloads:
            lines.append(
                f"Reveal metadata (from input {metadata['input_index']} — "
                f"1 of {n_payloads} glyphs minted here; see metadata_inputs for the rest):"
            )
        else:
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
        tl = metadata.get("timelock")
        if tl:
            lines.append(f"  timelock: opens at {tl['unlock_at']} ({tl['mode']})")
            if tl.get("hint"):
                lines.append(f"            hint: {_truncate_for_human(tl['hint'])}")
            lines.append(f"            cek commitment: {tl['cek_hash']}")
            # NO "unlocked/locked" LINE. Deciding that needs the caller's view of the chain — a tip
            # height for mode="block", a timestamp for mode="time" — and this renderer is handed a
            # payload, not a node. `pyrxd.is_unlocked(...)` answers it for a caller who has one.
            # Printing a verdict off this process's wall clock would be a guess dressed as a fact,
            # and for mode="block" it would be meaningless.
            lines.append("            (unlocked? pass this token's metadata and your chain tip to")
            lines.append("             pyrxd.is_unlocked / pyrxd.get_unlock_remaining)")
    # THE OTHER GLYPHS IN A MULTI-GLYPH REVEAL (#577). Pointing at a JSON key is
    # no use to someone reading the terminal, which is where this renderer is read.
    others = [
        row
        for row in (payload.get("metadata_inputs") or [])
        if row["input_index"] != (metadata or {}).get("input_index")
    ]
    if others:
        lines.append("")
        lines.append(f"Other glyphs minted in this transaction ({len(others)}):")
        for row in others:
            label = _truncate_for_human(row["name"] or row["ticker"] or "(unnamed)")
            lines.append(f"  input {row['input_index']:>3}: {row['classification']:<12} {label}")

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


def _op_return_payload_lines(payload: dict, indent: str = "  ") -> list[str]:
    """The `msg` and HashMark rendering, for EVERY human surface that shows one.

    Factored out because there are two such surfaces and there was one renderer. The
    pasted-script view printed the digest, the signer and the attestation verdict; the
    txid view — the DEFAULT path, and the only one that reaches a record actually on
    chain — printed the type label alone. So a v2 whose signature DOES NOT VERIFY and
    a genuine one rendered byte-identically, with the affirmative-sounding
    `op_return-hashmark-v2` label surviving and the verdict discarded.

    A computed verdict that no human sees is not a feature. Two copies of a renderer
    is how one of them ends up missing the line that matters, so there is one.
    """
    out: list[str] = []
    msg = payload.get("message")
    if msg:
        if msg["outcome"] == "ok":
            if msg["is_utf8"]:
                out.append(f"{indent}message ({msg['byte_length']} bytes): {_truncate_for_human(msg['text'])}")
            else:
                # Say WHY there is no text rather than printing nothing, or a caller
                # assumes the field is empty when the bytes simply are not text.
                out.append(f"{indent}message: {msg['byte_length']} bytes, not valid UTF-8 (see data_hex)")
        else:
            out.append(f"{indent}message: {msg['outcome']}" + (f" — {msg['detail']}" if msg.get("detail") else ""))

    hm = payload.get("hashmark")
    if hm:
        # HashMark is a third-party OP_RETURN format (MIT, github.com/cdonnachie/hashmark.rxd).
        # Classifying it in JSON and not printing it here would leave the feature
        # invisible to the person actually reading a terminal.
        if hm["outcome"] == "ok":
            out.append(f"{indent}HashMark v{hm['version']} ({hm['algorithm']})")
            out.append(f"{indent}  digest:  {hm['digest']}")
            if hm.get("label"):
                out.append(f"{indent}  label:   {_truncate_for_human(hm['label'])}")
            elif hm.get("label_withheld"):
                # v1 keeps its timestamp evidence; the label is withheld WITH a reason,
                # because silently showing nothing looks like a record that had no label.
                out.append(f"{indent}  label:   [withheld — {hm['label_withheld']}]")
            if hm.get("signer_hash160"):
                out.append(f"{indent}  signer:  {hm['signer_hash160']}")
                att = hm.get("attestation") or {}
                if att.get("outcome") == "valid":
                    out.append(f"{indent}  signature VERIFIED — recovers to the committed signer")
                    out.append(f"{indent}    (assuming {att.get('assumed_network')}; the chain is part of")
                    out.append(f"{indent}     the signed statement and a pasted script carries no context)")
                    wi = hm.get("wave_identity")
                    if wi and wi.get("resolved"):
                        names = wi.get("names") or []
                        if names:
                            out.append(f"{indent}  WAVE identity: {', '.join(names)}")
                            out.append(f"{indent}    (the signing key owns these names — file matches the")
                            out.append(f"{indent}     digest AND was recorded by that name's holder)")
                        else:
                            out.append(f"{indent}  WAVE identity: none — the signing key owns no WAVE name")
                    elif wi:
                        out.append(f"{indent}  WAVE identity: not resolved ({wi.get('reason')})")
                elif att.get("outcome") == "invalid_signature":
                    # The bytes decoded; the CLAIM does not hold. Saying "malformed"
                    # here would send whoever is debugging it after the wrong problem.
                    out.append(f"{indent}  signature DOES NOT VERIFY — {att.get('detail', 'no detail')}")
                    out.append(f"{indent}    (the record is well-formed; its claim is not supported)")
            out.append(f"{indent}  (proves someone knew this digest no later than the confirming")
            out.append(f"{indent}   block — not authorship, ownership, originality or contents)")
        else:
            out.append(f"{indent}HashMark: {hm['outcome']}" + (f" — {hm['detail']}" if hm.get("detail") else ""))

    return out


def _render_script_human(payload: dict) -> str:
    """Pretty-print a classified script result."""
    type_ = payload.get("type", "?")
    head = f"type: {type_}    length: {payload['length']} bytes"
    body: list[str] = []
    body.extend(_op_return_payload_lines(payload))

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
    elif type_ == "container-legacy":
        body.append(f"  ref:          {payload['ref_outpoint']}")
        body.append(f"  child_ref:    {payload['child_ref_outpoint']}")
        body.append(f"  owner_pkh:    {payload['owner_pkh']}")
        body.append("  *** UNSPENDABLE ***")
        body.append("  A pre-0.15.0 CONTAINER-with-child-ref output. OP_PUSHINPUTREF leaves")
        body.append("  the child ref on the stack, so the P2PKH tail hashes the ref instead of")
        body.append("  the pubkey and OP_EQUALVERIFY fails for every possible scriptSig. The")
        body.append("  photons on this output cannot be recovered, and the child NFT whose ref")
        body.append("  it names was consumed to create it and cannot be re-minted.")
        body.append("  Collection membership now lives in the envelope's 'in' field.")
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
    elif type_ == "p2sh":
        body.append(f"  script_hash: {payload['script_hash']}")
        body.append("  (pay-to-script-hash. The redeem script is not on-chain until this")
        body.append("   output is spent, so nothing further can be said about it here.)")
    elif type_ in ("p2pkh-cltv", "p2pkh-csv"):
        body.extend(_render_timelock_body(payload, type_))
    elif type_ == "soulbound-covenant":
        body.append(f"  variant:      {payload.get('variant', '?')}")
        body.append(f"  bound_ref:    {payload['bound_ref_outpoint']}")
        body.append(f"  owner_pkh:    {payload['owner_pkh']}")
        body.append(f"  self-replication branch: {payload['has_self_replication']}")
        body.append(f"  burn branch:             {payload['has_burn_branch']}")
        body.append("  NON-TRANSFERABLE AT CONSENSUS — the only spends this lock permits are")
        body.append("  a byte-identical self-clone or a burn. There is no transfer path.")
        body.append("  (exact match against pyrxd's soulbound covenant builder. It does NOT")
        body.append("   verify the bound ref names a live Glyph singleton, that the singleton")
        body.append("   is actually held here, or that the covenant is defect-free — the")
        body.append("   covenant is a pre-external-audit prototype.)")
    elif type_ == "self-replicating-covenant":
        body.append(f"  bound_ref:    {payload.get('bound_ref_outpoint', '(more than one ref)')}")
        body.append(f"  self-replication branch: {payload['has_self_replication']}")
        body.append(f"  burn branch:             {payload['has_burn_branch']}")
        body.append("  (structural marker match ONLY: this script binds a singleton ref and")
        body.append("   contains a self-replication-or-burn constraint, but its bytes are not")
        body.append("   a covenant pyrxd builds. That is NOT proof it is soulbound — container")
        body.append("   and vault covenants replicate themselves too. Read the script before")
        body.append("   trusting it as a credential.)")
        body.extend(_render_ref_summary_body(payload))
    elif type_ == "unknown":
        body.append("  (script does not match any known Glyph or P2PKH layout)")
        body.extend(_render_ref_summary_body(payload))
    return "\n".join([head, *body])


def _render_timelock_body(payload: dict, type_: str) -> list[str]:
    """The CLTV / CSV time-lock detail lines.

    These outputs are HTLC refund legs in practice, so the reader is usually
    asking "when can I spend this?". Say what the encoded value means in the
    unit it is actually denominated in, and never imply the lock has elapsed —
    that needs a chain tip (CLTV) or the funding output's confirmation height
    (CSV), neither of which a locking script carries.
    """
    body = [f"  owner_pkh:    {payload['owner_pkh']}"]
    basis = payload["locktime_basis"]
    units = payload["locktime_units"]
    if type_ == "p2pkh-cltv":
        # Two different numbers, one block apart, and printing only the first
        # answers a question nobody asked. OP_CLTV constrains the SPENDING TX's
        # nLockTime (>= the encoded value); IsFinalTx then requires that
        # nLockTime be STRICTLY LESS than the containing block's height/time.
        # So the encoded value is a floor on a tx field, and the earliest block
        # that can carry the spend is one past it. ``locktime_earliest`` is
        # derived in _inspect_core so every surface prints the same number.
        earliest = payload.get("locktime_earliest")
        body.append("  lock:         ABSOLUTE (OP_CHECKLOCKTIMEVERIFY)")
        if basis == "height":
            body.append(f"  requires:     spending tx nLockTime >= {units:,} (block height)")
            if earliest is not None:
                body.append(f"  earliest spend: a block at height {earliest:,} or later")
        else:
            body.append(f"  requires:     spending tx nLockTime >= {units} (Unix time; >= {LOCKTIME_THRESHOLD:,})")
            if earliest is not None:
                body.append(f"  earliest spend: the first block whose time-lock clock passes {earliest}")
        body.append("  The encoded value is a floor on the transaction's nLockTime, NOT a")
        body.append("  height at which this output turns spendable: consensus (IsFinalTx)")
        body.append("  requires nLockTime to be STRICTLY LESS than the height/time of the")
        body.append("  block containing the spend, so the encoded value itself is one block")
        body.append("  too early. The spending input's nSequence must also be non-final.")
    else:
        body.append("  lock:         RELATIVE (OP_CHECKSEQUENCEVERIFY, BIP-68/112)")
        body.append(f"  raw sequence: {payload['locktime_value']} (0x{payload['locktime_value']:x})")
        disabled = bool(payload.get("relative_lock_disabled"))
        # State the disable bit BEFORE the decoded delay. Printing "delay: 144
        # blocks" first and the "…but it is ignored" line after is how a reader
        # skimming the top of the block walks away with the opposite of the
        # truth.
        if disabled:
            body.append("  *** RELATIVE LOCK DISABLED — SPENDABLE IMMEDIATELY ***")
            body.append("  Bit 31 (SEQUENCE_LOCKTIME_DISABLE_FLAG) is set, so consensus ignores")
            body.append("  the relative lock entirely. The delay below is encoded in the script")
            body.append("  but enforces nothing. pyrxd's builder refuses to emit this shape.")
        prefix = "  delay (ignored):" if disabled else "  delay:       "
        if basis == "blocks":
            body.append(f"{prefix} {units:,} block(s) after this output confirms")
        else:
            body.append(f"{prefix} {units:,} x 512s = {units * 512:,}s after this output confirms")
        if not disabled:
            body.append("  The spending input's nSequence must carry at least this delay, and")
            body.append("  the spending tx must be version 2 or later.")
    body.append("  (structural pattern match; inspect cannot tell you whether the lock has")
    body.append("   already elapsed — that needs the chain tip / this output's confirmation)")
    return body


def _render_ref_summary_body(payload: dict) -> list[str]:
    """Report the input refs an unnamed script carries, if any.

    The one fact worth surfacing about a script no classifier claims: whether
    it is token-bearing. Spending a ref-carrying UTXO as plain funding burns
    the token it carries.

    ``input_refs`` is the CARRIED set (0xd0 / 0xd8 — Radiant's
    ``foundPushRefs``); ``referenced_refs`` is the set the script merely names
    (0xd1 require / 0xd2, 0xd3 disallow). Only the first burns when spent, so
    only the first gets the warning — see :func:`._ref_summary`.
    """
    token_bearing = payload.get("token_bearing")
    refs = payload.get("input_refs") or []
    named = payload.get("referenced_refs") or []
    # A script that merely gates on a ref is worth reporting, but never under
    # the burn warning — that is the false positive that trains readers to
    # ignore the real one.
    named_body: list[str] = []
    if named:
        named_body.append(f"  references (does NOT carry) {len(named)} ref(s):")
        for row in named:
            named_body.append(f"      {row['opcode']}  {row['ref_outpoint']}")
        named_body.append("  0xd1 OP_REQUIREINPUTREF gates on a ref being live among the spending")
        named_body.append("  tx's inputs; 0xd2/0xd3 forbid one. Neither holds a token here, so")
        named_body.append("  spending this output destroys nothing.")
    if token_bearing is None:
        return [
            "  token-bearing: UNKNOWN — the script does not decode as an opcode stream,",
            "  so the walk could not rule out an input ref. Treat it as token-bearing.",
        ]
    if not refs:
        return ["  token-bearing: no (the opcode-aware walk found no OP_PUSHINPUTREF/SINGLETON)", *named_body]
    body = [f"  token-bearing: YES — carries {len(refs)} input ref(s):"]
    for row in refs:
        body.append(f"      {row['opcode']}  {row['ref_outpoint']}")
    body.append("  Do NOT spend this as plain funding: a ref-carrying UTXO fed in as a fee")
    body.append("  input destroys the token it carries.")
    body.extend(named_body)
    return body


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
@click.option(
    "--verify-wave",
    "verify_wave",
    is_flag=True,
    default=False,
    help=(
        "For a VERIFIED HashMark v2 signature, look up the WAVE names the signing "
        "key owns. Needs the network. Never runs on an unverified signature."
    ),
)
@click.pass_obj
def inspect_cmd(ctx: CliContext, inspect_input: str, fetch: bool, resolve: bool, verify_wave: bool) -> None:
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
        type=p2sh         → script_hash
        type=nft / ft     → ref_txid, ref_vout, ref_outpoint, owner_pkh
        type=mut          → ref_txid, ref_vout, ref_outpoint, payload_hash
        type=commit-nft / commit-ft → payload_hash, owner_pkh
        type=dmint        → version (v1|v2), contract_ref_outpoint,
                            token_ref_outpoint, height, max_height, reward,
                            algo, daa_mode
        type=p2pkh-cltv   → owner_pkh, locktime_value, locktime_basis
                            ("height"|"unix_time"), locktime_units,
                            locktime_earliest. Absolute time-lock (BIP-65);
                            basis is decided by LOCKTIME_THRESHOLD
                            (500,000,000). locktime_units is the FLOOR on the
                            spending tx's nLockTime; locktime_earliest
                            (= locktime_units + 1) is the first block
                            height/time that can carry the spend, because
                            IsFinalTx requires nLockTime < the containing
                            block's height/time.
        type=p2pkh-csv    → owner_pkh, locktime_value, locktime_basis
                            ("blocks"|"time_512s"), locktime_units,
                            relative_lock_disabled. Relative time-lock
                            (BIP-68/112); relative_lock_disabled=true means
                            bit 31 is set and consensus ignores the lock.
        type=soulbound-covenant → variant ("fixed-index"|"composable"),
                            transferability, bound_ref_txid, bound_ref_vout,
                            bound_ref_outpoint, owner_pkh,
                            has_self_replication, has_burn_branch, note.
                            An EXACT match against pyrxd's soulbound builder:
                            the lock permits only a self-clone or a burn.
        type=self-replicating-covenant → has_self_replication,
                            has_burn_branch, bound_ref_outpoint (only when the
                            script binds exactly one ref), note,
                            token_bearing, input_refs[], referenced_refs[].
                            Structural MARKERS only — not proof the script is
                            a soulbound token. Carries NO transferability key,
                            deliberately: that field is the soulbound verdict
                            and this tier has not earned it.
        type=container-legacy → spendable (always false), ref_outpoint,
                            child_ref_outpoint, owner_pkh, note. A dead
                            pre-0.15.0 CONTAINER output; nothing can spend it.
        type=unknown      → token_bearing (true|false|null), input_refs[],
                            referenced_refs[]; each entry {opcode,
                            ref_outpoint}. token_bearing=null means the script
                            does not decode, so the absence of a ref is NOT
                            proven. input_refs[] is the CARRIED set (0xd0
                            OP_PUSHINPUTREF / 0xd8 OP_PUSHINPUTREFSINGLETON —
                            Radiant's foundPushRefs), and only those make an
                            output token-bearing. referenced_refs[] is the set
                            the script names without holding (0xd1
                            OP_REQUIREINPUTREF gates on one; 0xd2/0xd3 forbid
                            one); spending such an output destroys nothing.

    Script-level vs envelope-level: the type above is read from the LOCKING
    SCRIPT. The Glyph protocol labels that live in the reveal transaction's
    CBOR envelope — dat / container / authority / encrypted / timelock / wave —
    are a different classifier, reported under metadata.classification on the
    txid form only. A TIMELOCK *token* has no script signature to find; the
    p2pkh-cltv / p2pkh-csv types above are ordinary BIP-65/112 script locks and
    are unrelated to it.
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

    if verify_wave:
        _attach_wave_identity(ctx, payload)

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


def _attach_wave_identity(ctx: CliContext, payload: dict) -> None:
    """Resolve the WAVE names a VERIFIED HashMark signer owns, and attach them.

    ONLY runs on a signature that actually verified. Resolving an unverified
    signer would dress a claim up as an identity — the exact failure the
    signature check exists to prevent — so an unverified or absent attestation
    attaches nothing and says why.

    Errors are attached rather than raised: a name lookup failing is not a reason
    to lose the classification the user asked for.
    """
    # BOTH shapes. A pasted script puts the record at the top level; a txid puts one
    # per output. Reading only the first meant `--verify-wave <txid> --fetch` attached
    # nothing and never said why — a flag that silently does nothing on the form most
    # people use it with.
    records = (
        [payload["hashmark"]]
        if payload.get("hashmark")
        else [row["hashmark"] for row in (payload.get("outputs") or []) if row.get("hashmark")]
    )
    for hm in records:
        _resolve_one_wave_identity(ctx, hm)


def _resolve_one_wave_identity(ctx: CliContext, hm: dict) -> None:
    if not hm:
        return
    att = hm.get("attestation") or {}
    if att.get("outcome") != "valid":
        hm["wave_identity"] = {
            "resolved": False,
            "reason": (
                "signature did not verify; refusing to resolve an unproven signer"
                if att.get("outcome") == "invalid_signature"
                else "no verified v2 signature on this record"
            ),
        }
        return

    from ..glyph.wave import wave_names_for_hash160

    async def _do() -> list[str]:
        client = ctx.make_client()
        async with client:
            return await wave_names_for_hash160(client, bytes.fromhex(att["recovered_hash160"]))

    try:
        names = asyncio.run(_do())
    except Exception as exc:
        # The exception text can contain a server-controlled response body.
        hm["wave_identity"] = {"resolved": False, "reason": _sanitize_display_string(f"lookup failed: {exc}")}
        return
    # SANITIZED AT THE BOUNDARY, like every other name the indexer hands back. A
    # WAVE name is registration text an attacker chooses, and it lands directly
    # under "signature VERIFIED" — the one line in this output that states an
    # independently checked cryptographic fact. Raw, it can carry the ANSI to
    # scroll that line off the screen and reprint it saying something else.
    hm["wave_identity"] = {"resolved": True, "names": [_sanitize_display_string(n) for n in names]}
