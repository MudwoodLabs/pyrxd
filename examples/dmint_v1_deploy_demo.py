"""dMint V1 deploy demo — multi-contract permissionless-mint token.

This demo deploys a V1 dMint token (the only dMint format on Radiant
mainnet today). Unlike a plain Glyph FT deploy, dMint emits *N parallel
contract UTXOs* in the reveal — every contract can be mined from
independently, so claims race in parallel. Total supply equals
``num_contracts * max_height * reward_photons``.

The on-chain reference deployment is Radiant Glyph Protocol (GLYPH) at
mainnet commit ``a443d9df…878b`` / reveal ``b965b32d…9dd6``. This demo
emits byte-identical contract scripts when configured with the same
params (the M2 byte-equal golden vector tests pin this).

Run modes
---------

::

    # 1. Dry-run (builds txs but does NOT broadcast — the SAFE default):
    DRY_RUN=1 GLYPH_WIF=<wif> python examples/dmint_v1_deploy_demo.py

    # 2. Resume reveal phase after commit was broadcast:
    DRY_RUN=0 \\
    I_UNDERSTAND_THIS_IS_REAL=yes \\
    GLYPH_WIF=<wif> \\
    COMMIT_TXID=<txid> COMMIT_VOUT=<n> COMMIT_VALUE=<photons> \\
    python examples/dmint_v1_deploy_demo.py

    # 3. Full real broadcast (commit + reveal, BOTH on mainnet):
    DRY_RUN=0 \\
    I_UNDERSTAND_THIS_IS_REAL=yes \\
    GLYPH_WIF=<wif> \\
    python examples/dmint_v1_deploy_demo.py

Environment variables
---------------------

``DRY_RUN``          Default ``1``; ``0`` = build+broadcast.
                     Refuses to broadcast unless ``I_UNDERSTAND_THIS_IS_REAL=yes``.
``GLYPH_WIF``        Funded WIF private key.
``TOKEN_NAME``       Default ``"pyrxd V1 demo"``.
``TOKEN_TICKER``     Default ``"PXD"``.
``TOKEN_DESC``       Default ``"V1 dMint demo deploy via pyrxd"``.
``NUM_CONTRACTS``    Default ``4`` (keep small for the demo — real deploys
                     use 32+).
``MAX_HEIGHT``       Default ``100``.
``REWARD_PHOTONS``   Default ``1000``.
``DIFFICULTY``       Default ``1`` (very easy — anyone can mine).
``COMMIT_TXID``      Resume after broadcast: skip commit, go to reveal.
``COMMIT_VOUT``      Required when ``COMMIT_TXID`` is set (typically 0).
``COMMIT_VALUE``     Required when ``COMMIT_TXID`` is set.

Threat-model notes
------------------

* The three-key handshake (``DRY_RUN=0`` plus
  ``I_UNDERSTAND_THIS_IS_REAL=yes`` plus a real ``GLYPH_WIF``) is a
  deliberate footgun guard. A typo or leaked env var alone is not
  enough to broadcast.
* The demo refuses to spend token-bearing UTXOs as funding (mirrors
  ``find_dmint_funding_utxo`` from ``pyrxd.glyph.dmint``). A wallet
  that accidentally spends an FT/NFT/dMint UTXO destroys the token.
* Signing is atomic: all input preimages are computed first, then
  signed in a separate pass, then attached in a final pass. Partial
  failure leaves the tx untouched.

See ``docs/dmint-research-photonic-deploy.md`` for the byte-by-byte
chain truth this demo emits against.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import websockets

from pyrxd.fee_models import SatoshisPerKilobyte
from pyrxd.glyph import GlyphBuilder, GlyphMetadata, GlyphProtocol
from pyrxd.glyph.builder import DmintV1DeployParams
from pyrxd.glyph.dmint import is_token_bearing_script
from pyrxd.hash import sha256
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH, encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction, TransactionInput, TransactionOutput

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

ELECTRUMX_WS_URL = os.environ.get("PYRXD_ELECTRUMX", "wss://electrumx.radiant4people.com:50022/")
DRY_RUN: bool = os.environ.get("DRY_RUN", "1") != "0"
I_UNDERSTAND: bool = os.environ.get("I_UNDERSTAND_THIS_IS_REAL", "").strip().lower() == "yes"

GLYPH_WIF: str = os.environ.get("GLYPH_WIF", "")
TOKEN_NAME = os.environ.get("TOKEN_NAME", "pyrxd V1 demo")
TOKEN_TICKER = os.environ.get("TOKEN_TICKER", "PXD")
TOKEN_DESC = os.environ.get("TOKEN_DESC", "V1 dMint demo deploy via pyrxd")
NUM_CONTRACTS = int(os.environ.get("NUM_CONTRACTS", "4"))
MAX_HEIGHT = int(os.environ.get("MAX_HEIGHT", "100"))
REWARD_PHOTONS = int(os.environ.get("REWARD_PHOTONS", "1000"))
DIFFICULTY = int(os.environ.get("DIFFICULTY", "1"))

# Resume after commit-broadcast (skip commit phase).
RESUME_COMMIT_TXID = os.environ.get("COMMIT_TXID", "").lower()
RESUME_COMMIT_VOUT = int(os.environ.get("COMMIT_VOUT", "0"))
RESUME_COMMIT_VALUE = int(os.environ.get("COMMIT_VALUE", "0")) if RESUME_COMMIT_TXID else 0
RESUME_FILE = ".dmint_v1_deploy_demo.resume.json"

MIN_FEE_RATE = 10_000  # photons per byte (post-V2 mainnet)

# ---------------------------------------------------------------------------
# ElectrumX client (minimal — matches ft_deploy_premine.py's helpers)
# ---------------------------------------------------------------------------


async def _ws_call(method: str, params: list) -> object:
    """Single round-trip ElectrumX JSON-RPC call."""
    async with websockets.connect(ELECTRUMX_WS_URL) as ws:
        await ws.send(json.dumps({"id": 1, "method": method, "params": params}))
        resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=30.0))
        if resp.get("error"):
            raise RuntimeError(f"ElectrumX error for {method}: {resp['error']}")
        return resp["result"]


async def fetch_utxos(address: str) -> list:
    locking = P2PKH().lock(address)
    sh = sha256(locking.serialize()).hex()
    rev = "".join(reversed([sh[i : i + 2] for i in range(0, len(sh), 2)]))
    raw = await _ws_call("blockchain.scripthash.listunspent", [rev])
    if not isinstance(raw, list):
        return []
    return raw


async def fetch_raw_tx(txid: str) -> bytes:
    raw_hex = await _ws_call("blockchain.transaction.get", [txid, False])
    if not isinstance(raw_hex, str):
        raise RuntimeError(f"unexpected raw-tx response type for {txid}")
    return bytes.fromhex(raw_hex)


async def broadcast(tx_hex: str) -> str:
    result = await _ws_call("blockchain.transaction.broadcast", [tx_hex])
    if not isinstance(result, str):
        raise RuntimeError(f"unexpected broadcast response: {result!r}")
    return result


# ---------------------------------------------------------------------------
# Token-burn defense
# ---------------------------------------------------------------------------


async def _filter_plain_funding_utxos(utxos: list, address: str) -> list:
    """Remove any UTXO whose source script is token-bearing.

    Mirrors `find_dmint_funding_utxo`'s opcode-aware classifier from
    `pyrxd.glyph.dmint`: never spend an FT/NFT/dMint UTXO as funding —
    that destroys the token. Naive byte-substring scans misclassify
    legitimate P2PKHs (compound doc: funding-utxo-byte-scan-dos.md).
    Use the same `is_token_bearing_script` helper the library uses.
    """
    safe: list = []
    for u in utxos:
        try:
            raw = await fetch_raw_tx(u["tx_hash"])
        except Exception as e:
            print(f"  [skip] could not fetch source tx for {u['tx_hash']}: {e}")
            continue
        tx = Transaction.from_hex(raw)
        if tx is None or u["tx_pos"] >= len(tx.outputs):
            continue
        script = tx.outputs[u["tx_pos"]].locking_script.serialize()
        if is_token_bearing_script(script):
            print(
                f"  [skip] token-bearing UTXO {u['tx_hash'][:12]}…:{u['tx_pos']} "
                f"({u['value']:,} photons) — would destroy the token"
            )
            continue
        safe.append(u)
    return safe


# ---------------------------------------------------------------------------
# Atomic multi-input signing
# ---------------------------------------------------------------------------


def _sign_p2pkh_inputs(
    tx: Transaction,
    indices: list[int],
    private_key: PrivateKey,
    *,
    suffix_by_index: dict[int, bytes] | None = None,
) -> None:
    """Sign multiple inputs atomically (three-pass: build, sign, attach).

    Why three-pass: per security S4 in the M2 plan, a build-sign-attach
    loop that mutates the tx mid-iteration would leave a half-signed tx
    on partial failure (key access failure, OOM, etc.). The three-pass
    pattern builds all preimages first, signs all preimages second, and
    attaches all unlocking scripts in a final pass — if any step raises,
    the tx is left untouched.

    :param tx:                The transaction to sign in place.
    :param indices:           Input indices to sign (all P2PKH).
    :param private_key:       Private key for every input (single-key
                              demo; production would pass per-input keys).
    :param suffix_by_index:   Optional dict mapping input index to a
                              scriptSig suffix appended after the
                              ``<sig> <pubkey>`` push (used for the FT
                              and NFT reveal inputs that carry the
                              Glyph payload).
    """
    suffix_by_index = suffix_by_index or {}

    # Pass 1: build every preimage. If any input's metadata is malformed
    # this raises before we sign anything.
    preimages: list[bytes] = []
    for idx in indices:
        preimages.append(tx.preimage(idx))

    # Pass 2: produce every signature. Key access failures surface
    # here, still without mutating the tx.
    pub = private_key.public_key().serialize()
    sigs: list[bytes] = []
    for preimage in preimages:
        sigs.append(private_key.sign(preimage))

    # Pass 3: build full unlocking scripts and attach in one sweep.
    unlocks: list[bytes] = []
    for idx, sig in zip(indices, sigs, strict=True):
        sighash = tx.inputs[idx].sighash
        unlock = encode_pushdata(sig + sighash.to_bytes(1, "little")) + encode_pushdata(pub)
        if idx in suffix_by_index:
            unlock += suffix_by_index[idx]
        unlocks.append(unlock)
    for idx, unlock in zip(indices, unlocks, strict=True):
        tx.inputs[idx].unlocking_script = Script(unlock)


# ---------------------------------------------------------------------------
# Unlock-script templates (used by tx.sign() during fee estimation)
# ---------------------------------------------------------------------------


def _p2pkh_unlock_template(private_key: PrivateKey):
    """Standard P2PKH unlock template — pass-through to library helper."""

    def sign(tx, idx):
        sig = private_key.sign(tx.preimage(idx))
        sighash = tx.inputs[idx].sighash
        pub = private_key.public_key().serialize()
        return Script(encode_pushdata(sig + sighash.to_bytes(1, "little")) + encode_pushdata(pub))

    def estimated_len():
        return 107

    return to_unlock_script_template(sign, estimated_len)


def _reveal_input_unlock_template(private_key: PrivateKey, scriptsig_suffix: bytes):
    """Unlock template for a Glyph commit-hashlock spend: P2PKH-sig + suffix."""

    def sign(tx, idx):
        sig = private_key.sign(tx.preimage(idx))
        sighash = tx.inputs[idx].sighash
        pub = private_key.public_key().serialize()
        p2pkh_part = encode_pushdata(sig + sighash.to_bytes(1, "little")) + encode_pushdata(pub)
        return Script(p2pkh_part + scriptsig_suffix)

    def estimated_len():
        return 107 + len(scriptsig_suffix)

    return to_unlock_script_template(sign, estimated_len)


# ---------------------------------------------------------------------------
# Commit tx builder (1 FT-commit + N ref-seeds + 1 change)
# ---------------------------------------------------------------------------


def _build_commit_tx(
    utxos: list,
    private_key: PrivateKey,
    commit_script: bytes,
    num_contracts: int,
    address: str,
    pkh: Hex20,
) -> Transaction:
    """Build the V1 dMint deploy commit tx.

    Output layout (mirrors the on-chain GLYPH commit at
    ``a443d9df…878b`` documented in
    ``docs/dmint-research-photonic-deploy.md`` §2):

    * vout 0:        the 75-byte FT-commit hashlock
    * vouts 1..N:    ``num_contracts`` × 1-photon P2PKH ref-seeds
    * vout N+1:      P2PKH change

    Note: the on-chain GLYPH commit also had a 75-byte *NFT-commit*
    hashlock at vout N+1 (for the auth NFT). The pyrxd M2 demo skips
    this — see ``docs/dmint-research-photonic-deploy.md`` §6 for the
    "mint-fresh vs forward-prior" decision: M2 picks mint-fresh
    *without* the auth NFT to keep the demo focused on the dMint
    machinery itself. A future milestone can layer the auth NFT on top.
    """
    p2pkh_lock = P2PKH().lock(address)

    inputs: list[TransactionInput] = []
    total_in = 0
    # Commit needs: 1 (FT-commit) + num_contracts × 1 (ref-seeds) + change.
    # Reveal will then consume the FT-commit + each ref-seed plus a
    # funding input for the reveal fee. Conservative estimate: keep
    # 500K photons over the commit-out minimum to cover reveal fees.
    target_value = 1 + num_contracts + 500_000
    for u in utxos:
        src_out = TransactionOutput(p2pkh_lock, u["value"])

        class _SrcTx:
            def __init__(self, out, pos):
                self.outputs = {pos: out}

        inp = TransactionInput(
            source_txid=u["tx_hash"],
            source_output_index=u["tx_pos"],
            unlocking_script_template=_p2pkh_unlock_template(private_key),
        )
        inp.satoshis = u["value"]
        inp.locking_script = p2pkh_lock
        inp.source_transaction = _SrcTx(src_out, u["tx_pos"])
        inputs.append(inp)
        total_in += u["value"]
        if total_in >= target_value:
            break

    if total_in < target_value:
        raise ValueError(
            f"Insufficient funds: have {total_in:,}, need ≥{target_value:,} photons "
            f"(1 commit + {num_contracts} ref-seeds + reveal budget). Top up the wallet."
        )

    outputs: list[TransactionOutput] = [
        TransactionOutput(Script(commit_script), 1),  # vout 0: FT-commit
    ]
    for _ in range(num_contracts):
        outputs.append(TransactionOutput(p2pkh_lock, 1))  # vouts 1..N: ref-seeds
    outputs.append(TransactionOutput(p2pkh_lock, change=True))

    tx = Transaction(tx_inputs=inputs, tx_outputs=outputs)
    tx.fee(SatoshisPerKilobyte(MIN_FEE_RATE * 1000))
    tx.sign()
    return tx


# ---------------------------------------------------------------------------
# Reveal tx builder (N dMint contracts + change)
# ---------------------------------------------------------------------------


def _build_reveal_tx(
    commit_txid: str,
    num_contracts: int,
    cbor_bytes: bytes,
    scriptsig_suffix: bytes,
    contract_scripts: tuple[bytes, ...],
    op_return_script: bytes | None,
    funding_utxo: dict,
    funding_pkh_lock: bytes,
    private_key: PrivateKey,
    address: str,
) -> Transaction:
    """Build the V1 dMint deploy reveal tx.

    Reveal layout (simplified from GLYPH — no auth NFT):

    * vin 0:          spends commit vout 0 (FT-commit hashlock) with
                      ``<sig> <pubkey> <gly> <CBOR>``
    * vins 1..N:      spend commit vouts 1..N (ref-seeds, P2PKH)
    * vin N+1:        plain funding input for reveal fees
    * vouts 0..N-1:   ``num_contracts`` V1 dMint contract UTXOs
    * vout N:         optional OP_RETURN (omitted if not set)
    * vout N | N+1:   P2PKH change to deployer

    All inputs except vin 0 are P2PKH; vin 0 carries the Glyph reveal
    payload via ``scriptsig_suffix``. Signing is delegated to
    ``tx.sign()`` (which invokes the unlock templates above) — same
    pattern as ``examples/ft_deploy_premine.py``.
    """
    p2pkh_lock = P2PKH().lock(address)

    class _SrcTx:
        def __init__(self, outs):
            self.outputs = outs

    # Reconstruct the commit's outputs (vout 0 = FT-commit, vouts 1..N = ref-seeds)
    # so each TransactionInput can resolve satoshis + locking_script.
    # We don't have the actual commit_script here (the caller passed
    # `scriptsig_suffix` derived from CBOR, but the FT-commit locking
    # script is the standard 75-byte shape; in DRY_RUN mode we just need
    # SOMETHING that round-trips through .preimage()).
    commit_outs = {0: TransactionOutput(p2pkh_lock, 1)}
    for i in range(1, num_contracts + 1):
        commit_outs[i] = TransactionOutput(p2pkh_lock, 1)
    src_commit = _SrcTx(commit_outs)

    inputs: list[TransactionInput] = []

    # vin 0: FT-commit hashlock — needs the reveal suffix.
    inp0 = TransactionInput(
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=_reveal_input_unlock_template(private_key, scriptsig_suffix),
    )
    inp0.satoshis = 1
    inp0.locking_script = p2pkh_lock
    inp0.source_transaction = src_commit
    inputs.append(inp0)

    # vins 1..N: ref-seed P2PKHs.
    for i in range(1, num_contracts + 1):
        inp = TransactionInput(
            source_txid=commit_txid,
            source_output_index=i,
            unlocking_script_template=_p2pkh_unlock_template(private_key),
        )
        inp.satoshis = 1
        inp.locking_script = p2pkh_lock
        inp.source_transaction = src_commit
        inputs.append(inp)

    # vin N+1: external funding for reveal fees.
    funding_src = _SrcTx({funding_utxo["tx_pos"]: TransactionOutput(Script(funding_pkh_lock), funding_utxo["value"])})
    fund = TransactionInput(
        source_txid=funding_utxo["tx_hash"],
        source_output_index=funding_utxo["tx_pos"],
        unlocking_script_template=_p2pkh_unlock_template(private_key),
    )
    fund.satoshis = funding_utxo["value"]
    fund.locking_script = Script(funding_pkh_lock)
    fund.source_transaction = funding_src
    inputs.append(fund)

    outputs: list[TransactionOutput] = [TransactionOutput(Script(s), 1) for s in contract_scripts]
    if op_return_script is not None:
        outputs.append(TransactionOutput(Script(op_return_script), 0))
    outputs.append(TransactionOutput(p2pkh_lock, change=True))

    tx = Transaction(tx_inputs=inputs, tx_outputs=outputs)
    tx.fee(SatoshisPerKilobyte(MIN_FEE_RATE * 1000))
    tx.sign()
    return tx


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    if not GLYPH_WIF:
        print("ERROR: Set GLYPH_WIF to a funded WIF private key.", file=sys.stderr)
        sys.exit(1)

    if not DRY_RUN and not I_UNDERSTAND:
        print(
            "ERROR: DRY_RUN=0 requires I_UNDERSTAND_THIS_IS_REAL=yes (broadcasts a real mainnet tx).",
            file=sys.stderr,
        )
        sys.exit(1)

    private_key = PrivateKey(GLYPH_WIF)
    pub = private_key.public_key()
    address = pub.address()
    pkh = Hex20(pub.hash160())

    total_supply = NUM_CONTRACTS * MAX_HEIGHT * REWARD_PHOTONS
    print(f"Deployer wallet: {address}")
    print(f"Token name:      {TOKEN_NAME}")
    print(f"Ticker:          {TOKEN_TICKER}")
    print(f"num_contracts:   {NUM_CONTRACTS}")
    print(f"max_height:      {MAX_HEIGHT}")
    print(f"reward_photons:  {REWARD_PHOTONS}")
    print(f"difficulty:      {DIFFICULTY}")
    print(f"Total supply:    {total_supply:,} photons ({NUM_CONTRACTS} × {MAX_HEIGHT} × {REWARD_PHOTONS})")
    print(f"DRY_RUN:         {DRY_RUN}")
    print()

    metadata = GlyphMetadata(
        protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
        name=TOKEN_NAME,
        ticker=TOKEN_TICKER,
        description=TOKEN_DESC,
    )

    builder = GlyphBuilder()
    params = DmintV1DeployParams(
        metadata=metadata,
        owner_pkh=pkh,
        num_contracts=NUM_CONTRACTS,
        max_height=MAX_HEIGHT,
        reward_photons=REWARD_PHOTONS,
        difficulty=DIFFICULTY,
    )
    result = builder.prepare_dmint_deploy(params)
    print(f"Payload hash:   {result.commit_result.payload_hash.hex()}")
    print(f"CBOR ({len(result.cbor_bytes)} bytes): {result.cbor_bytes.hex()}")
    print(f"Placeholder contract script length: {len(result.placeholder_contract_scripts[0])} bytes")
    print()

    # Commit phase.
    if RESUME_COMMIT_TXID:
        commit_txid = RESUME_COMMIT_TXID
        print(f"Resuming from commit {commit_txid} (vout {RESUME_COMMIT_VOUT}, {RESUME_COMMIT_VALUE:,} photons)")
    else:
        print("Fetching UTXOs and filtering token-bearing...")
        utxos = await fetch_utxos(address)
        if not utxos:
            print("No UTXOs found. Fund the address and retry.", file=sys.stderr)
            sys.exit(1)
        utxos = await _filter_plain_funding_utxos(utxos, address)
        if not utxos:
            print("No plain (non-token-bearing) UTXOs available.", file=sys.stderr)
            sys.exit(1)
        total = sum(u["value"] for u in utxos)
        print(f"  → {len(utxos)} plain UTXO(s), {total:,} photons")

        commit_tx = _build_commit_tx(
            utxos=utxos,
            private_key=private_key,
            commit_script=result.commit_result.commit_script,
            num_contracts=NUM_CONTRACTS,
            address=address,
            pkh=pkh,
        )
        commit_txid = commit_tx.txid()
        print(f"Commit tx:      {commit_txid}")
        print(f"  size:         {commit_tx.byte_length()} bytes")
        print(f"  fee:          {commit_tx.get_fee():,} photons")
        print()

        resume_info = {
            "commit_txid": commit_txid,
            "num_contracts": NUM_CONTRACTS,
            "cbor_hex": result.cbor_bytes.hex(),
        }
        with open(RESUME_FILE, "w") as f:
            json.dump(resume_info, f)
        print(f"Resume info saved to {RESUME_FILE}")

        if DRY_RUN:
            print("[DRY RUN] Commit tx NOT broadcast.")
            print(f"  Resume env: COMMIT_TXID={commit_txid} COMMIT_VOUT=0 COMMIT_VALUE=1")
            print(f"\nCommit hex (for review):\n{commit_tx.hex()}")
            return

        print("Broadcasting commit tx...")
        txid = await broadcast(commit_tx.hex())
        print(f"Broadcast: {txid}")
        print("Waiting 90s for commit to confirm before reveal...")
        await asyncio.sleep(90)

    # Reveal phase — rebuild contract scripts with the real commit txid.
    reveal_scripts = result.build_reveal_outputs(commit_txid)
    print(
        f"Contract scripts built (N={len(reveal_scripts.contract_scripts)}, "
        f"each {len(reveal_scripts.contract_scripts[0])} bytes)"
    )

    # Need a separate plain funding UTXO for reveal fees (the commit
    # already consumed its inputs; the ref-seeds + FT-commit are all
    # 1-photon outputs, not enough for fee). Fetch + filter.
    print("Fetching reveal-fee funding UTXO...")
    utxos = await fetch_utxos(address)
    utxos = await _filter_plain_funding_utxos(utxos, address)
    # Pick the largest.
    utxos.sort(key=lambda u: u["value"], reverse=True)
    if not utxos:
        print("ERROR: no plain UTXO available to fund reveal fees.", file=sys.stderr)
        sys.exit(1)
    funding = utxos[0]
    print(f"  → using {funding['tx_hash'][:12]}…:{funding['tx_pos']} ({funding['value']:,} photons)")

    reveal_tx = _build_reveal_tx(
        commit_txid=commit_txid,
        num_contracts=NUM_CONTRACTS,
        cbor_bytes=reveal_scripts.cbor_bytes,
        scriptsig_suffix=reveal_scripts.scriptsig_suffix,
        contract_scripts=reveal_scripts.contract_scripts,
        op_return_script=reveal_scripts.op_return_script,
        funding_utxo=funding,
        funding_pkh_lock=bytes(P2PKH().lock(address).serialize()),
        private_key=private_key,
        address=address,
    )
    print(f"Reveal tx:      {reveal_tx.txid()}")
    print(f"  size:         {reveal_tx.byte_length()} bytes")
    print(f"  fee:          {reveal_tx.get_fee():,} photons")

    if DRY_RUN:
        print("\n[DRY RUN] Reveal tx NOT broadcast.")
        print(f"\nReveal hex (for review):\n{reveal_tx.hex()[:200]}…")
        return

    print("\nBroadcasting reveal tx...")
    rev_txid = await broadcast(reveal_tx.hex())
    print(f"Broadcast: {rev_txid}")
    print()
    print("Token deployed!")
    print(f"  Token ref:   {commit_txid}:0")
    print(f"  Contracts:   {NUM_CONTRACTS} parallel UTXOs at {rev_txid}:0..{NUM_CONTRACTS - 1}")
    print(f"  Total supply: {total_supply:,} photons")


if __name__ == "__main__":
    asyncio.run(main())
