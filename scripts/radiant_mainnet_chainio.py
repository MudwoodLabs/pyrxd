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
import shlex
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

    # F-010: this shim ONLY targets the mainnet node (container 'radiant-mainnet'); the
    # RXD audit-gate network is therefore always mainnet — never a free CLI choice. The
    # runner pins the leg/keys network to this so a --rxd-network flag cannot disable
    # require_audit_cleared while still broadcasting real value to mainnet.
    NETWORK: str = "bc"

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
        """Build the ssh argv.

        ssh ALWAYS joins the remote command words with spaces into a single string and
        hands that to the remote login SHELL, which re-parses it. So a remote arg with
        spaces or shell-special chars (the scantxoutset descriptor JSON: spaces, quotes,
        ``[]{}``) is mangled unless we quote it for the REMOTE shell. We shlex.quote each
        remote token so the remote shell reconstructs exactly the argv we intend. (The
        prior version relied on a bare space-join and silently corrupted JSON args — the
        scantxoutset failure that stalled the dust run.) Inputs are still our own
        hex/ints/known-method-names + the descriptor we build, never untrusted strings.
        """
        inner = ["docker", "exec", self._container, "radiant-cli"]
        if self._rpcwallet:
            inner.append(f"-rpcwallet={self._rpcwallet}")
        inner += list(cli_args)
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
        # scantxoutset descriptor "raw(<spk hex>)". ssh joins the remote argv with
        # SPACES into one shell command string, so the descriptor JSON must contain NO
        # spaces or the remote shell word-splits it (e.g. '[{"desc": "raw(..)"}]' splits
        # at the space after the colon -> scantxoutset rejects a malformed action). Use
        # compact separators so the whole descriptor stays a single shell token.
        desc = json.dumps([{"desc": f"raw({spk.hex()})"}], separators=(",", ":"))
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

    # -- fee-UTXO carving (the RXD covenant spend needs a separate plain fee input) ---
    def carve_fee_input(self, amount_photons: int, fee_photons: int = 4_000_000):
        """Carve a plain-P2PKH fee UTXO from the wallet -> a gravity.htlc_spend.FeeInput.

        SYNCHRONOUS (called from FeeSource.next_fee_input, which the leg invokes inside
        an awaited spend — the ssh calls block, but the carve is a quick wallet op; if
        this ever lands on a hot async path, wrap it in asyncio.to_thread like _run).
        Mirrors the regtest _FeeSource: pick the biggest wallet UTXO, dumpprivkey it,
        build+sign a 1-in/2-out tx (fee output + change) with the repo Transaction
        builder, broadcast, return the fee output as input 0. Targets the wallet named
        by rpcwallet, or the single loaded (often unnamed) wallet if rpcwallet is empty.

        Default ``fee_photons`` covers the carve tx's OWN relay fee (the tr mainnet
        node runs relayfee 0.10 RXD/kB; a ~340-byte carve needs >= 3.4M photons).
        ``amount_photons`` is what the carved UTXO holds — that becomes the fee paid
        BY the covenant spend, which is far larger (~11 KB) and needs ~100M+ photons
        at the same rate. Caller picks both.
        """
        from pyrxd.gravity.htlc_spend import FeeInput
        from pyrxd.keys import PrivateKey
        from pyrxd.script.script import Script
        from pyrxd.script.type import encode_pushdata, to_unlock_script_template
        from pyrxd.security.types import Hex20
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        utxos = self._run_sync("listunspent", "1", "9999999")
        if not isinstance(utxos, list) or not utxos:
            raise RuntimeError("no spendable wallet UTXOs to carve a fee input")
        u = max(utxos, key=lambda x: x["amount"])
        wif = str(self._run_sync("dumpprivkey", u["address"]))
        key = PrivateKey(wif)
        pkh = bytes(Hex20(key.public_key().hash160()))
        spk = bytes.fromhex(u["scriptPubKey"])
        in_sats = round(u["amount"] * 1e8)
        change = in_sats - amount_photons - fee_photons
        if change <= 546:
            raise RuntimeError(f"selected UTXO too small to carve {amount_photons} + fee {fee_photons}")

        def _src(txid, vout, s, v):
            outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(vout)]
            outs.append(TransactionOutput(Script(s), v))
            tx = Transaction(tx_inputs=[], tx_outputs=outs)
            tx.txid = lambda: txid  # type: ignore[method-assign]
            return tx

        def _unlock(tx, idx):
            inp = tx.inputs[idx]
            sig = key.sign(tx.preimage(idx))
            return Script(
                encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(key.public_key().serialize())
            )

        fin = TransactionInput(
            source_transaction=_src(u["txid"], u["vout"], spk, in_sats),
            source_txid=u["txid"],
            source_output_index=u["vout"],
            unlocking_script_template=to_unlock_script_template(_unlock, lambda: 110),
        )
        fin.satoshis = in_sats
        fin.locking_script = Script(spk)
        out_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
        tx = Transaction(
            tx_inputs=[fin],
            tx_outputs=[TransactionOutput(Script(out_spk), amount_photons), TransactionOutput(Script(out_spk), change)],
        )
        tx.sign()
        txid = self._run_sync("sendrawtransaction", tx.serialize().hex())
        if not isinstance(txid, str):
            raise RuntimeError("fee carve broadcast did not return a txid")
        return FeeInput(txid=txid, vout=0, value=amount_photons, scriptpubkey=out_spk, wif=wif)
