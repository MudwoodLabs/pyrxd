#!/usr/bin/env python3
"""OPS SHIM (not the shipped package): a RadiantChainIO client over `ssh tr`.

This is the mainnet RXD transport for the dust-mainnet swap runbook. It is
DELIBERATELY in scripts/, NOT in src/pyrxd: the standing production transport for
RadiantChainIO should be a real ElectrumX/Fulcrum RPC client. `ssh tr 'docker exec
radiant-mainnet radiant-cli …'` is the only mainnet RXD access we have right now, so
this shim exists for the one-shot, operator-supervised dust run — file the Fulcrum
client as the known interim follow-up.

Implements exactly the duck-typed client surface RadiantChainIO needs
(`broadcast` / `get_transaction_verbose` / `get_utxos`); pass an instance to
`RadiantChainIO(client)` from the run script.

Safety constraints (dust-mainnet plan, architecture review):
* The blocking `ssh` subprocess runs in `asyncio.to_thread` so it does NOT stall the
  async coordinator's event loop (RadiantChainIO.broadcast/confirmations are async).
* ALL dynamic arguments (covenant SPK hex, txids, the scantxoutset descriptor) are
  passed as argv LIST elements — never shell-interpolated. There is no `shell=True`
  and no f-string-into-a-shell-command anywhere here.
* get_utxos resolves a covenant SPK from a registry (the run script registers it),
  because RadiantChainIO hands get_utxos the ElectrumX script_hash = sha256(spk)[::-1]
  and radiant-cli has no scripthash index — scantxoutset needs the raw SPK.

USE ONLY against the mainnet RXD node for the dust run; it moves real value.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess

from pyrxd.network.electrumx import UtxoRecord


class SshTrRadiantClient:
    """radiant-cli-over-ssh client satisfying RadiantChainIO's 3 methods.

    Parameters
    ----------
    ssh_host:
        The ssh alias for the mainnet Radiant host (default "tr").
    container:
        The docker container running the mainnet node (default "radiant-mainnet").
    rpcwallet:
        Optional wallet name for wallet RPCs.
    ssh_timeout_s:
        Per-call timeout for the ssh subprocess.
    """

    def __init__(
        self,
        *,
        ssh_host: str = "tr",
        container: str = "radiant-mainnet",
        rpcwallet: str | None = None,
        ssh_timeout_s: int = 30,
    ) -> None:
        self._ssh_host = ssh_host
        self._container = container
        self._rpcwallet = rpcwallet
        self._timeout = ssh_timeout_s
        self._spk_by_hash: dict[bytes, bytes] = {}

    def register_spk(self, spk: bytes) -> None:
        """Register a covenant SPK so get_utxos can resolve it from its script_hash."""
        self._spk_by_hash[hashlib.sha256(bytes(spk)).digest()[::-1]] = bytes(spk)

    # -- transport ----------------------------------------------------------
    def _cli_argv(self, *cli_args: str) -> list[str]:
        """Build the argv (NO shell). Every cli_arg is a discrete list element."""
        inner = ["radiant-cli"]
        if self._rpcwallet:
            inner.append(f"-rpcwallet={self._rpcwallet}")
        inner += list(cli_args)
        # ssh runs `docker exec <container> radiant-cli …`. Passed as one remote
        # command list; ssh joins them with spaces, but since WE control the argv and
        # never interpolate untrusted strings into a shell string, there is no
        # injection surface (the args are hex/ints/known method names).
        return ["ssh", "-o", "ConnectTimeout=10", self._ssh_host, "docker", "exec", self._container, *inner]

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
        # Blocking ssh off the event loop (architecture review).
        return await asyncio.to_thread(self._run_sync, *cli_args)

    # -- RadiantChainIO client surface --------------------------------------
    async def broadcast(self, raw_tx: bytes) -> str:
        return str(await self._run("sendrawtransaction", bytes(raw_tx).hex()))

    async def get_transaction_verbose(self, txid: str) -> dict:
        res = await self._run("getrawtransaction", str(txid), "true")
        if not isinstance(res, dict):
            raise RuntimeError("getrawtransaction did not return a verbose dict")
        return res

    async def get_utxos(self, script_hash: bytes) -> list[UtxoRecord]:
        spk = self._spk_by_hash.get(bytes(script_hash))
        if spk is None:
            return []  # unregistered SPK -> no UTXOs (the leg fail-closes on empty)
        # scantxoutset descriptor "raw(<spk hex>)" — the hex is a discrete argv element
        # inside a JSON array string; no shell, no interpolation into a command line.
        desc = json.dumps([{"desc": f"raw({spk.hex()})"}])
        res = await self._run("scantxoutset", "start", desc)
        if not isinstance(res, dict):
            raise RuntimeError("scantxoutset did not return a dict")
        tip = int(await self._run("getblockcount"))
        out: list[UtxoRecord] = []
        for u in res.get("unspents", []):
            height = int(u.get("height", 0))
            confs = (tip - height + 1) if height else 0
            out.append(
                UtxoRecord(tx_hash=u["txid"], tx_pos=int(u["vout"]), value=round(u["amount"] * 1e8), height=confs)
            )
        return out
