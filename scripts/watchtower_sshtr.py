#!/usr/bin/env python3
"""Read-ONLY RXD source for the watchtower over ``ssh tr 'docker exec … radiant-cli'``.

The watchtower runner (``scripts/watchtower_run.py``) targets a public ElectrumX URL by
default; this shim lets it watch against the team's mainnet node on ssh host ``tr`` (the
only mainnet RXD access available) instead.

It exposes EXACTLY the two methods ``ElectrumRxdChainSource`` needs —
``get_tip_height()`` + ``get_transaction_verbose(txid)`` — and **nothing else**. There is
deliberately NO broadcast / wallet / fee-carving surface (unlike the dust-run shim
``radiant_mainnet_chainio.py``): the watchtower v1 is alert-only and must never be able to
move value, so the capability simply isn't here.

Safety (mirrors the proven invocation in ``radiant_mainnet_chainio.py``): every token is
``shlex.quote``d for the remote shell, there is no ``shell=True``, and the blocking ssh
runs in ``asyncio.to_thread`` off the event loop. All args are our own method names /
txids — never untrusted input.

``get_transaction_verbose`` calls ``getrawtransaction <txid> true``, which requires the
node to resolve the tx (txindex, or the covenant tx otherwise known) — the same call the
dust runs used for covenant confirmations, so it is proven against ``tr``.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import subprocess

__all__ = ["SshTrRxdReader"]


class SshTrRxdReader:
    """Read-only radiant-cli-over-ssh RXD source (``get_tip_height`` + ``get_transaction_verbose``)."""

    def __init__(
        self,
        *,
        ssh_host: str = "tr",
        container: str = "radiant-mainnet",
        ssh_timeout_s: int = 30,
    ) -> None:
        self._ssh_host = ssh_host
        self._container = container
        self._timeout = ssh_timeout_s

    def _cli_argv(self, *cli_args: str) -> list[str]:
        inner = ["docker", "exec", self._container, "radiant-cli", *cli_args]
        remote = " ".join(shlex.quote(tok) for tok in inner)
        return ["ssh", "-o", "ConnectTimeout=10", self._ssh_host, remote]

    def _run_sync(self, *cli_args: str) -> object:
        r = subprocess.run(self._cli_argv(*cli_args), capture_output=True, text=True, timeout=self._timeout)
        if r.returncode != 0:
            raise RuntimeError(f"ssh radiant-cli {cli_args[:1]} failed: {r.stderr.strip()[:200]}")
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    async def _run(self, *cli_args: str) -> object:
        return await asyncio.to_thread(self._run_sync, *cli_args)

    # -- the ElectrumRxdChainSource client surface (read-only) ---------------
    async def get_tip_height(self) -> int:
        return int(await self._run("getblockcount"))

    async def get_transaction_verbose(self, txid: str) -> dict:
        res = await self._run("getrawtransaction", str(txid), "true")
        if not isinstance(res, dict):
            raise RuntimeError("getrawtransaction did not return a verbose dict")
        return res
