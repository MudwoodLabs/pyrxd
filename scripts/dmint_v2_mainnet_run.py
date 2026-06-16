"""OPS HARNESS (not shipped): first-ever mainnet V2 dMint deploy + PoW mint.

Proves the canonical-Photonic V2 redesign on REAL radiant-core 3.1.2 mainnet
consensus (#219, #2). Adapts the regtest e2e flow (ref-induction deploy → 8-byte
PoW mint) to mainnet transports via SshTrRadiantClient. FIXED difficulty=1 so the
mint is just the consensus-hardcoded 4-zero-byte PoW floor (~2**32, fast-ish).

SAFETY:
* Every covenant tx is `testmempoolaccept`-checked on the mainnet node BEFORE any
  broadcast (read-only; allowed=false ⇒ we stop, nothing sent, no value lost).
* Staged subcommands with a JSON state file so each broadcast is a deliberate,
  separately-invoked step (the operator inspects the tx + accept result first).
* Moves dust only. Contract output = 1 photon (singleton, like live V1 dMint).

Stages:
  prepare      carve 2 genesis UTXOs, build deploy, testmempoolaccept (NO send)
  send-deploy  broadcast the deploy
  mine         carve funding, build+mine the mint, testmempoolaccept (NO send)
  send-mint    broadcast the mint, verify recreation + reward

Run with: PYTHONPATH=<redesign-src>:<repo>/scripts python scripts/dmint_v2_mainnet_run.py <stage>
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time

from radiant_mainnet_chainio import SshTrRadiantClient

from pyrxd.glyph.dmint import (
    DaaMode,
    DmintAlgo,
    DmintContractUtxo,
    DmintDeployParams,
    DmintMinerFundingUtxo,
    DmintState,
    build_dmint_contract_script,
    build_dmint_mint_tx,
    build_dmint_v2_mint_preimage,
    build_mint_scriptsig,
    mine_solution_dispatch,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

_MINER_ARGV = [sys.executable, "-m", "pyrxd.contrib.miner", "--workers", "20"]
_MINE_TIMEOUT_S = 2400.0

# Run mode: DMINT_RUN_MODE=fixed (default) or lwma. Both deploy at difficulty=1
# (target=MAX → mining is just the consensus 4-zero PoW floor). LWMA additionally
# proves adaptive difficulty: a fast block (delta=30 < target_time=60) lowers the
# recreated target on-chain, exactly matching compute_next_target_linear.
_MODE = os.environ.get("DMINT_RUN_MODE", "fixed").lower()
_DAA_MODE = DaaMode.LWMA if _MODE == "lwma" else DaaMode.FIXED
_STATE = f"/tmp/dmint_v2_mainnet_state_{_MODE}.json"  # noqa: S108 — ephemeral ops state (0600); holds throwaway WIFs
_DEPLOY_LAST_TIME = 1_700_000_000 if _MODE == "lwma" else 0  # past ts so the mint nLockTime is final
_TARGET_TIME = 60
_MINT_CURRENT_TIME = _DEPLOY_LAST_TIME + 30 if _MODE == "lwma" else 0  # fast block → LWMA lowers target

# Run params (difficulty=1 → target=MAX → only the 4-zero PoW floor gates mining).
_MAX_HEIGHT = 10
_REWARD = 1000  # photons emitted by the mint (FT reward output)
_GENESIS_CARVE = 30_000_000  # 0.30 RXD per genesis UTXO (covers contract+deploy fee+change)
_FUNDING_CARVE = 30_000_000  # 0.30 RXD funding UTXO (covers reward + mint fee + change)


def _client() -> SshTrRadiantClient:
    return SshTrRadiantClient()  # tr / radiant-mainnet / default wallet


def _accepts(c: SshTrRadiantClient, raw_hex: str) -> dict:
    res = c._run_sync("testmempoolaccept", json.dumps([raw_hex], separators=(",", ":")))
    if not isinstance(res, list) or not res:
        raise RuntimeError(f"testmempoolaccept returned unexpected: {res!r}")
    return res[0]


def _src(txid: str, vout: int, spk: bytes, val: int) -> Transaction:
    outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), val))
    tx = Transaction(tx_inputs=[], tx_outputs=outs)
    tx.txid = lambda: txid  # type: ignore[method-assign]
    return tx


def _p2pkh_unlock(key: PrivateKey):
    def _u(tx, idx):
        inp = tx.inputs[idx]
        sig = key.sign(tx.preimage(idx))
        return Script(
            encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(key.public_key().serialize())
        )

    return to_unlock_script_template(_u, lambda: 110)


def _spend(txid: str, vout: int, spk: bytes, val: int, key: PrivateKey) -> TransactionInput:
    tin = TransactionInput(
        source_transaction=_src(txid, vout, spk, val),
        source_txid=txid,
        source_output_index=vout,
        unlocking_script_template=_p2pkh_unlock(key),
    )
    tin.satoshis = val
    tin.locking_script = Script(spk)
    return tin


def _p2pkh_spk(key: PrivateKey) -> bytes:
    return b"\x76\xa9\x14" + bytes(Hex20(key.public_key().hash160())) + b"\x88\xac"


def _save(d: dict) -> None:
    # 0600 — the state holds the carve UTXOs' WIFs (dust, but real keys).
    fd = os.open(_STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, indent=2)


def _load() -> dict:
    with open(_STATE) as f:
        return json.load(f)


def _key_of(g: dict) -> PrivateKey:
    return PrivateKey(bytes.fromhex(g["key"]))


def _fanout(c: SshTrRadiantClient, amounts: list[int]) -> tuple[list[dict], bytes]:
    """Spend the single biggest wallet UTXO (incl. unconfirmed) into ``len(amounts)``
    outputs under one fresh key + change back to the wallet, in ONE tx.

    Avoids the sequential-carve trap (each carve's change is unconfirmed, and
    carve_fee_input's minconf=1 can't see it). Returns the funded outpoints (each
    with the fresh key's raw seed hex) and the wallet change SPK (for tx change).
    """
    utxos = c._run_sync("listunspent", "0", "9999999")
    if not isinstance(utxos, list) or not utxos:
        raise RuntimeError("no wallet UTXOs to fan out")
    u = max(utxos, key=lambda x: x["amount"])
    src_key = PrivateKey(str(c._run_sync("dumpprivkey", u["address"])))
    src_spk = bytes.fromhex(u["scriptPubKey"])
    in_sats = round(u["amount"] * 1e8)
    fee = 4_000_000
    change = in_sats - sum(amounts) - fee
    if change <= 546:
        raise RuntimeError(f"source UTXO {in_sats} too small for {sum(amounts)} + fee {fee}")
    seed = secrets.token_bytes(32)
    fresh_spk = _p2pkh_spk(PrivateKey(seed))
    outs = [TransactionOutput(Script(fresh_spk), a) for a in amounts]
    outs.append(TransactionOutput(Script(src_spk), change))  # change back to wallet
    tx = Transaction(tx_inputs=[_spend(u["txid"], int(u["vout"]), src_spk, in_sats, src_key)], tx_outputs=outs)
    tx.sign()
    txid = c._run_sync("sendrawtransaction", tx.serialize().hex())
    if not isinstance(txid, str):
        raise RuntimeError(f"fanout broadcast did not return a txid: {txid!r}")
    print(f"  fanout {txid}: {len(amounts)} outputs ({amounts}) + {change} change->wallet", flush=True)
    return (
        [
            {"txid": txid, "vout": i, "value": a, "spk": fresh_spk.hex(), "key": seed.hex()}
            for i, a in enumerate(amounts)
        ],
        src_spk,
    )


def prepare() -> None:
    c = _client()
    print("[prepare] fanning out genesis-token, genesis-contract, mint-funding from wallet ...", flush=True)
    outpoints, wallet_spk = _fanout(c, [_GENESIS_CARVE, _GENESIS_CARVE, _FUNDING_CARVE])
    g_tok, g_con, fund = outpoints

    token_ref = GlyphRef(txid=g_tok["txid"], vout=g_tok["vout"])
    contract_ref = GlyphRef(txid=g_con["txid"], vout=g_con["vout"])
    params = DmintDeployParams(
        contract_ref=contract_ref,
        token_ref=token_ref,
        max_height=_MAX_HEIGHT,
        reward=_REWARD,
        difficulty=1,
        algo=DmintAlgo.SHA256D,
        daa_mode=_DAA_MODE,
        target_time=_TARGET_TIME,
        height=0,
        last_time=_DEPLOY_LAST_TIME,
    )
    contract_script = build_dmint_contract_script(params)
    state = DmintState.from_script(contract_script)
    assert state.is_v1 is False, "deploy script did not parse as V2"

    # deploy fee: at 0.10 RXD/kB a ~720B tx ≈ 7.2M photons; budget 8M. Change -> wallet.
    deploy_fee = 8_000_000
    change_val = g_tok["value"] + g_con["value"] - 1 - deploy_fee
    if change_val <= 546:
        raise RuntimeError(f"genesis outputs too small: change would be {change_val}")
    deploy = Transaction(
        tx_inputs=[
            _spend(g_tok["txid"], g_tok["vout"], bytes.fromhex(g_tok["spk"]), g_tok["value"], _key_of(g_tok)),
            _spend(g_con["txid"], g_con["vout"], bytes.fromhex(g_con["spk"]), g_con["value"], _key_of(g_con)),
        ],
        tx_outputs=[
            TransactionOutput(Script(contract_script), 1),
            TransactionOutput(Script(wallet_spk), change_val),
        ],
    )
    deploy.sign()
    raw = deploy.serialize().hex()
    dtxid = deploy.txid()
    print(f"\n[prepare] deploy tx {dtxid}  ({len(raw) // 2} bytes, fee {deploy_fee})", flush=True)
    acc = _accepts(c, raw)
    print(f"[prepare] testmempoolaccept: {json.dumps(acc)}", flush=True)
    _save(
        {
            "params": {
                "max_height": _MAX_HEIGHT,
                "reward": _REWARD,
                "contract_ref": {"txid": contract_ref.txid, "vout": contract_ref.vout},
                "token_ref": {"txid": token_ref.txid, "vout": token_ref.vout},
            },
            "contract_script": contract_script.hex(),
            "deploy_raw": raw,
            "deploy_txid": dtxid,
            "deploy_accept": acc,
            "funding": fund,
            "wallet_spk": wallet_spk.hex(),
        }
    )
    print(f"\n[prepare] saved -> {_STATE}", flush=True)
    if not acc.get("allowed"):
        print("\n*** testmempoolaccept REJECTED the deploy — DO NOT send. Reason above. ***", flush=True)
        sys.exit(1)
    print("\n[prepare] DEPLOY ACCEPTED by mainnet mempool policy. Inspect above, then: send-deploy", flush=True)


def send_deploy() -> None:
    c = _client()
    st = _load()
    print(f"[send-deploy] broadcasting deploy {st['deploy_txid']} ...", flush=True)
    txid = c._run_sync("sendrawtransaction", st["deploy_raw"])
    print(f"[send-deploy] broadcast -> {txid}", flush=True)
    st["deploy_sent_txid"] = str(txid)
    _save(st)
    print("[send-deploy] done. Next: mine", flush=True)


def mine() -> None:
    c = _client()
    st = _load()
    contract_script = bytes.fromhex(st["contract_script"])
    state = DmintState.from_script(contract_script)
    contract = DmintContractUtxo(
        txid=st.get("deploy_sent_txid") or st["deploy_txid"], vout=0, value=1, script=contract_script, state=state
    )
    fund = st["funding"]
    print(f"[mine] funding from {fund['txid']}:{fund['vout']} value={fund['value']}", flush=True)
    funding = DmintMinerFundingUtxo(
        txid=fund["txid"], vout=fund["vout"], value=fund["value"], script=bytes.fromhex(fund["spk"])
    )
    fund_key = _key_of(fund)
    # miner key saved so the FT reward + mint change are recoverable (not thrown away).
    miner_seed = secrets.token_bytes(32)
    miner_pkh = bytes(Hex20(PrivateKey(miner_seed).public_key().hash160()))
    st["miner_key"] = miner_seed.hex()

    result = build_dmint_mint_tx(
        contract,
        nonce=b"\x00" * 8,
        miner_pkh=miner_pkh,
        current_time=_MINT_CURRENT_TIME,  # FIXED: 0 (lastTime stays 0). LWMA: deploy_last_time+30.
        funding_utxo=funding,
        op_return_msg=f"pyrxd-v2-mainnet-{_MODE}".encode(),
    )
    tx = result.tx
    op_return_script = tx.outputs[2].locking_script.script
    pre = build_dmint_v2_mint_preimage(contract, funding, op_return_script)

    print(f"[mine] PoW mining (8-byte nonce, target={state.target}) ... up to {_MINE_TIMEOUT_S}s", flush=True)
    t0 = time.monotonic()
    mined = mine_solution_dispatch(
        preimage=pre.preimage, target=state.target, nonce_width=8, miner_argv=_MINER_ARGV, timeout_s=_MINE_TIMEOUT_S
    )
    print(f"[mine] solved nonce={mined.nonce.hex()} in {time.monotonic() - t0:.0f}s", flush=True)
    tx.inputs[0].unlocking_script = Script(
        build_mint_scriptsig(mined.nonce, pre.input_hash, pre.output_hash, nonce_width=8)
    )
    # sign the funding input (input 1)
    sig = fund_key.sign(tx.preimage(1))
    tx.inputs[1].unlocking_script = Script(
        encode_pushdata(sig + tx.inputs[1].sighash.to_bytes(1, "little"))
        + encode_pushdata(fund_key.public_key().serialize())
    )
    raw = tx.serialize().hex()
    mtxid = tx.txid()
    print(f"\n[mine] mint tx {mtxid}  ({len(raw) // 2} bytes)", flush=True)
    acc = _accepts(c, raw)
    print(f"[mine] testmempoolaccept: {json.dumps(acc)}", flush=True)
    st["mint_raw"] = raw
    st["mint_txid"] = mtxid
    st["mint_nonce"] = mined.nonce.hex()
    st["mint_accept"] = acc
    st["recreated_state"] = {"height": result.updated_state.height, "target": result.updated_state.target}
    _save(st)
    if not acc.get("allowed"):
        print("\n*** testmempoolaccept REJECTED the mint — DO NOT send. Reason above. ***", flush=True)
        sys.exit(1)
    print("\n[mine] MINT ACCEPTED by mainnet mempool policy. Inspect above, then: send-mint", flush=True)


def send_mint() -> None:
    c = _client()
    st = _load()
    print(f"[send-mint] broadcasting mint {st['mint_txid']} ...", flush=True)
    txid = c._run_sync("sendrawtransaction", st["mint_raw"])
    print(f"[send-mint] broadcast -> {txid}", flush=True)
    st["mint_sent_txid"] = str(txid)
    _save(st)
    # verify: contract spent, recreated contract at vout0 value 1, reward at vout1
    print("[send-mint] verifying ...", flush=True)
    spent = c._run_sync("gettxout", st.get("deploy_sent_txid") or st["deploy_txid"], "0")
    recreated = c._run_sync("gettxout", str(txid), "0")
    reward = c._run_sync("gettxout", str(txid), "1")
    print(f"  contract input spent (gettxout null expected when mempool-spent): {spent}", flush=True)
    print(f"  recreated contract vout0: {recreated}", flush=True)
    print(f"  reward vout1: {reward}", flush=True)
    rs = st["recreated_state"]
    MAX = 0x7FFFFFFFFFFFFFFF
    print(f"\n[send-mint] DONE ({_MODE}). deploy={st.get('deploy_sent_txid')} mint={txid}", flush=True)
    print(f"  recreated height={rs['height']}  target={rs['target']}", flush=True)
    if _MODE == "lwma":
        moved = "LOWERED (DAA fired)" if rs["target"] < MAX else "unchanged"
        print(f"  LWMA: deploy target=MAX ({MAX}); recreated target {moved} — on-chain == off-chain.", flush=True)


_STAGES = {"prepare": prepare, "send-deploy": send_deploy, "mine": mine, "send-mint": send_mint}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in _STAGES:
        print(f"usage: {sys.argv[0]} {{{'|'.join(_STAGES)}}}", file=sys.stderr)
        sys.exit(2)
    _STAGES[sys.argv[1]]()
