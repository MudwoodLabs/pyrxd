"""Private helpers for the ``pyrxd glyph …`` commands.

Extracted from :mod:`pyrxd.cli.glyph_cmds` to keep that module focused on
command flow. Everything here is package-internal (underscore-prefixed) and
imported by ``glyph_cmds``:

* metadata file parsing + scaffolding (``_read_metadata_file``,
  ``_TEMPLATE_TYPES``, ``_scaffold_for``),
* the pre-broadcast confirmation summary (``_BroadcastSummary``,
  ``_confirm_or_abort``, ``_metadata_summary``),
* the Glyph reveal unlock-script builder (``_build_glyph_unlock``),
* Glyph ref parsing (``_parse_ref``, ``_try_extract_ft_ref``).

These are glyph-specific; the shared ``_load_wallet`` lives in
:mod:`pyrxd.cli.prompts` (it is used by query commands too).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from ..script.script import Script
from ..script.type import encode_pushdata, to_unlock_script_template
from ..security.errors import ValidationError
from ..security.types import Txid
from .context import CliContext
from .errors import UserError
from .prompts import confirm_action

if TYPE_CHECKING:
    from ..keys import PrivateKey


# ---------------------------------------------------------------------------
# Metadata file parsing + scaffolding
# ---------------------------------------------------------------------------


def _read_metadata_file(path: Path) -> GlyphMetadata:
    """Parse a metadata.json scaffold into a GlyphMetadata.

    The scaffold uses simple Python-friendly keys (``protocol`` as a
    list of strings rather than ints, etc.) so users don't have to
    learn the on-wire CBOR field names. Maps to GlyphMetadata here.
    """
    if not path.exists():
        raise UserError(
            f"metadata file not found: {path}",
            cause="the path does not resolve to a file",
            fix="run `pyrxd glyph init-metadata --type nft --out metadata.json` to scaffold one",
        )
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise UserError(
            f"could not read metadata file: {path}",
            cause=str(exc),
            fix="check that the file is valid JSON",
        ) from exc

    if not isinstance(data, dict):
        raise UserError("metadata file must contain a JSON object")

    # Convert protocol names → GlyphProtocol ints.
    raw_protocol = data.get("protocol", [])
    if not isinstance(raw_protocol, list) or not raw_protocol:
        raise UserError(
            "metadata.protocol must be a non-empty list",
            cause=f"got {type(raw_protocol).__name__}: {raw_protocol!r}",
            fix='use e.g. ["NFT"] or ["FT"] or ["FT", "DMINT"]',
        )

    proto_ints: list[int] = []
    for p in raw_protocol:
        if isinstance(p, int):
            proto_ints.append(p)
            continue
        if isinstance(p, str):
            try:
                proto_ints.append(int(GlyphProtocol[p.upper()]))
                continue
            except KeyError:
                raise UserError(
                    f"unknown protocol name: {p!r}",
                    fix=f"valid names: {sorted(p.name for p in GlyphProtocol)}",
                ) from None
        raise UserError(f"protocol entries must be string or int, got {type(p).__name__}")

    try:
        return GlyphMetadata(
            protocol=proto_ints,
            name=data.get("name", ""),
            ticker=data.get("ticker", ""),
            description=data.get("description", ""),
            token_type=data.get("token_type", ""),
            attrs=data.get("attrs", {}) or {},
            loc=data.get("loc", ""),
            loc_hash=data.get("loc_hash", ""),
            decimals=int(data.get("decimals", 0)),
            image_url=data.get("image_url", ""),
            image_ipfs=data.get("image_ipfs", ""),
            image_sha256=data.get("image_sha256", ""),
        )
    except ValidationError as exc:
        raise UserError(
            "metadata file failed validation",
            cause=str(exc),
            fix="see the error above; check protocol combinations and decimals range",
        ) from exc


_TEMPLATE_TYPES = ("nft", "ft", "dmint-ft", "mutable-nft", "container-nft")


def _scaffold_for(kind: str) -> dict:
    """Return a metadata.json template for *kind* (one of _TEMPLATE_TYPES)."""
    base = {
        "name": "My Token",
        "description": "Replace with a one- or two-line description.",
        "image_url": "",
        "image_ipfs": "",
        "image_sha256": "",
        "attrs": {},
    }
    if kind == "nft":
        return {**base, "protocol": ["NFT"], "token_type": "art"}  # nosec B105 — Glyph token-type tag, not a password
    if kind == "ft":
        return {
            **base,
            "protocol": ["FT"],
            "ticker": "MTK",
            "decimals": 0,
            # Note: 1 photon = 1 FT unit; "decimals" is display-only.
        }
    if kind == "dmint-ft":
        return {
            **base,
            "protocol": ["FT", "DMINT"],
            "ticker": "MTK",
            "decimals": 0,
        }
    if kind == "mutable-nft":
        return {**base, "protocol": ["NFT", "MUT"], "token_type": "mutable"}  # nosec B105 — token-type tag
    if kind == "container-nft":
        return {**base, "protocol": ["NFT", "CONTAINER"], "token_type": "collection"}  # nosec B105 — token-type tag
    # Should be unreachable thanks to click.Choice.
    raise UserError(f"unknown template type: {kind}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Broadcast confirmation summary
# ---------------------------------------------------------------------------


@dataclass
class _BroadcastSummary:
    """One section of the confirmation summary printed before a broadcast."""

    title: str
    lines: list[str]


def _confirm_or_abort(ctx: CliContext, sections: list[_BroadcastSummary]) -> None:
    """Print summary; ask for y/N. Raises UserError on abort."""
    ok, why = ctx.is_destructive_mode_safe()
    if not ok:
        raise UserError(why or "destructive op without --yes in --json mode")

    summary_lines = []
    for sec in sections:
        summary_lines.append(f"\n  {sec.title}:")
        summary_lines.extend(f"    {line}" for line in sec.lines)
    summary_lines.append("")  # blank line before the prompt

    if not confirm_action(summary_lines, ctx=ctx, prompt_text="Broadcast?"):
        raise UserError(
            "aborted by user",
            cause="confirmation prompt declined",
            fix="re-run with the inputs you actually want to broadcast",
        )


def _metadata_summary(metadata: GlyphMetadata) -> _BroadcastSummary:
    """Surface user-readable metadata fields in the broadcast summary.

    Threat model finding S7 (docs/threat-model.md): users running
    `glyph mint-nft` from a metadata.json may not realize what
    they're actually committing. The funding key, owner_pkh, etc. all
    come from the wallet/CLI args (not the file), so theft via this
    path is constrained — but the user should still see the
    metadata-driven name, ticker, protocol, and any creator/royalty
    fields before broadcasting. If something looks wrong (e.g., the
    file claims a name they didn't author), they can abort.
    """
    proto_names = ", ".join(GlyphProtocol(p).name for p in metadata.protocol)
    lines = [
        f"protocol:    [{proto_names}]",
        f"name:        {metadata.name or '(empty)'}",
    ]
    if metadata.ticker:
        lines.append(f"ticker:      {metadata.ticker}")
    if metadata.token_type:
        lines.append(f"token_type:  {metadata.token_type}")
    if metadata.description:
        # Truncate long descriptions; they don't change the security
        # posture but the summary should stay scannable.
        desc = metadata.description if len(metadata.description) <= 80 else metadata.description[:77] + "..."
        lines.append(f"description: {desc}")
    if metadata.image_url:
        lines.append(f"image_url:   {metadata.image_url}")
    if metadata.image_sha256:
        lines.append(f"image_hash:  {metadata.image_sha256[:16]}...{metadata.image_sha256[-8:]}")
    if metadata.creator:
        lines.append(f"creator:     pubkey={metadata.creator.pubkey[:16]}...")
    if metadata.royalty:
        lines.append(f"royalty:     {metadata.royalty.bps} bps → {metadata.royalty.address}")
        if metadata.royalty.splits:
            for addr, bps in metadata.royalty.splits:
                lines.append(f"             split: {bps} bps → {addr}")
    return _BroadcastSummary(title="Metadata", lines=lines)


# ---------------------------------------------------------------------------
# Glyph reveal unlock-script builder
# ---------------------------------------------------------------------------


def _build_glyph_unlock(privkey: PrivateKey, scriptsig_suffix: bytes):
    """Return an UnlockingScriptTemplate that signs P2PKH then appends Glyph suffix.

    Mirrors examples/glyph_mint_demo.py glyph_reveal_unlock.
    """

    def sign(tx, input_index):
        tx_input = tx.inputs[input_index]
        sighash = tx_input.sighash
        signature = privkey.sign(tx.preimage(input_index))
        pubkey = privkey.public_key().serialize()
        p2pkh_part = encode_pushdata(signature + sighash.to_bytes(1, "little")) + encode_pushdata(pubkey)
        return Script(p2pkh_part + scriptsig_suffix)

    def estimated_unlocking_byte_length() -> int:
        return 107 + len(scriptsig_suffix)

    return to_unlock_script_template(sign, estimated_unlocking_byte_length)


# ---------------------------------------------------------------------------
# Glyph ref parsing
# ---------------------------------------------------------------------------


def _parse_ref(s: str) -> GlyphRef:
    """Parse 'txid:vout' into a GlyphRef. UserError on invalid input."""
    if ":" not in s:
        raise UserError(
            f"ref must be 'txid:vout', got {s!r}",
            fix="example: a443d9df...:0",
        )
    txid_s, vout_s = s.split(":", 1)
    try:
        txid = Txid(txid_s)
        vout = int(vout_s)
    except (ValidationError, ValueError) as exc:
        raise UserError("invalid ref", cause=str(exc)) from exc
    return GlyphRef(txid=txid, vout=vout)


def _try_extract_ft_ref(script: bytes) -> GlyphRef | None:
    """Best-effort extract of the FT ref from a locking script."""
    from ..glyph.script import extract_ref_from_ft_script

    try:
        return extract_ref_from_ft_script(script)
    except Exception:
        return None
