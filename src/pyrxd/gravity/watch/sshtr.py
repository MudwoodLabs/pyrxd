#!/usr/bin/env python3
"""Read-ONLY RXD source for the watchtower over ``ssh <host> 'docker exec <container> radiant-cli ...'``.

The watchtower runner (``pyrxd.gravity.watch.run``, console script ``pyrxd-watchtower``)
targets a public ElectrumX URL by default (``--rxd-backend electrumx``); this reader lets an
operator instead watch against their own Radiant node over ssh (``--rxd-backend ssh-tr`` /
``--rxd-include-node``), reachable as ``ssh <ssh_host> 'docker exec <container> radiant-cli ...'``.
Both ``ssh_host`` and ``container`` are required (no built-in default): this ships in the
public wheel, so it must not bake in any one operator's private infrastructure.

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
import subprocess  # nosec B404  # read-only; every call site below is a fixed, shlex-quoted argv

__all__ = ["SshTrRxdReader"]


class SshTrRxdReader:
    """Read-only radiant-cli-over-ssh RXD source (``get_tip_height`` + ``get_transaction_verbose``)."""

    def __init__(
        self,
        *,
        ssh_host: str,
        container: str,
        ssh_timeout_s: int = 30,
    ) -> None:
        # ``ssh_host`` / ``container`` are REQUIRED, no default: this reader ships in the public
        # wheel and must not bake in any one operator's private ssh host / docker container name.
        self._ssh_host = ssh_host
        self._container = container
        self._timeout = ssh_timeout_s

    def _cli_argv(self, *cli_args: str) -> list[str]:
        inner = ["docker", "exec", self._container, "radiant-cli", *cli_args]
        remote = " ".join(shlex.quote(tok) for tok in inner)
        return ["ssh", "-o", "ConnectTimeout=10", self._ssh_host, remote]

    def _run_sync(self, *cli_args: str) -> object:
        # controlled list-form argv (own method names / txids, no shell=True) — see the module
        # docstring's Safety section
        r = subprocess.run(  # nosec B603
            self._cli_argv(*cli_args), capture_output=True, text=True, timeout=self._timeout
        )
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
