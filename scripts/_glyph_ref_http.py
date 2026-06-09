"""Mainnet Glyph genesis-ref authenticity adapter over the RXinDexer REST api (via ssh tr).

The proven REF gate (``pyrxd.gravity.radiant_leg.RxinDexerRefAdapter``) resolves a genesis ref via
the RXinDexer ElectrumX ws method ``glyph.get_token``. The mainnet RXinDexer deployment on ``tr``
runs only the **REST api** (``:8000``, bound to tr-localhost — no electrumx glyph ws), so this adapter
resolves the same fact over HTTP instead.

Key fact (read from the RXinDexer source ``electrumx/server/rest_api.py`` + verified live 2026-06-04):
``GET /tokens/{ref}`` keys a token on its **72-hex wire ref** == ``GlyphRef.to_bytes().hex()`` ==
the api's returned ``token_id`` (e.g. ``ff5c20f6…:0`` → ``40e98ec5…00000000``). A resolvable token IS
a genuine ``gly`` reveal; an unknown ref (the R1 fake-singleton forgery) → HTTP 404 → ``None`` → the
gate fails closed. Implements the ``RefAuthenticityIndexer`` protocol (one async ``resolve_ref``).
"""

from __future__ import annotations

import asyncio
import json
import shlex
import struct

from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.gravity.ref_authenticity import ResolvedRef
from pyrxd.security.errors import NetworkError, ValidationError


class SshTrHttpRefAdapter:
    """Resolve a genesis ref via ``ssh <host> curl http://<api>/tokens/{72-hex-ref}``.

    ``chain_io`` (a :class:`RadiantChainIO` over the same ssh-tr RXD client) supplies the genesis
    tx's confirmations — the ``glyph.get_token`` REST response does not carry confs."""

    def __init__(
        self,
        *,
        chain_io: RadiantChainIO,
        ssh_host: str = "tr",
        api_base: str = "http://127.0.0.1:8000",
        timeout_s: int = 15,
    ) -> None:
        if not isinstance(chain_io, RadiantChainIO):
            raise ValidationError("SshTrHttpRefAdapter requires a RadiantChainIO")
        self._chain_io = chain_io
        self._ssh_host = ssh_host
        self._base = api_base.rstrip("/")
        self._timeout = int(timeout_s)

    async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
        ref = GlyphRef.from_bytes(bytes(genesis_ref))  # validates the 36-byte wire ref (raises -> fail-closed)
        # The REST URL keys on the DISPLAY-order txid + little-endian vout (verified live: querying
        # ff5c20f6…:0 resolves). The api then RETURNS the INTERNAL-order token_id (== the wire ref ==
        # GlyphRef.to_bytes().hex()), which is what we bind against. (Asymmetric, but confirmed.)
        query_ref = ref.txid + struct.pack("<I", ref.vout).hex()
        token_id_expected = bytes(genesis_ref).hex()  # internal order == the response token_id
        body, code = await self._api_get(f"/tokens/{query_ref}")
        if code == 404:
            return None  # unknown token -> R1 forgery / not a real glyph -> gate fails closed
        if code != 200:
            raise NetworkError(f"RXinDexer REST /tokens/{query_ref} -> HTTP {code}: {body[:160]!r}")
        try:
            token = json.loads(body)
        except json.JSONDecodeError as exc:
            raise NetworkError(f"RXinDexer REST returned non-JSON: {body[:160]!r}") from exc
        if not isinstance(token, dict):
            raise NetworkError(f"RXinDexer REST returned {type(token).__name__}, expected an object")
        # Bind the resolution to the queried ref: the api's token_id MUST equal the wire ref (the
        # token is genuinely minted at THIS genesis outpoint). A mismatch fails closed.
        token_id = str(token.get("token_id", "")).lower()
        if token_id != token_id_expected.lower():
            return None
        confs = await self._chain_io.confirmations(ref.txid)
        return ResolvedRef(
            genesis_outpoint=bytes(genesis_ref),
            has_gly_marker=True,  # a resolvable RXinDexer token is a genuine gly reveal
            payload_hash=b"",  # REST api does not expose the envelope payload hash; gate uses it only if expected set
            confirmations=confs,
        )

    async def _api_get(self, path: str) -> tuple[str, int]:
        """``ssh <host> curl <api><path>`` → (body, http_status). The api is tr-localhost-bound."""
        remote = f"curl -s -m {self._timeout} -w '\\n%{{http_code}}' {shlex.quote(self._base + path)}"
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", self._ssh_host, remote]
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=self._timeout + 12)
        text = out.decode(errors="replace")
        nl = text.rfind("\n")
        body, code_s = (text[:nl], text[nl + 1 :].strip()) if nl >= 0 else (text, "")
        try:
            return body, int(code_s)
        except ValueError as exc:
            raise NetworkError(f"RXinDexer REST query failed (ssh/curl): {err.decode(errors='replace')[:160] or text[:160]!r}") from exc
