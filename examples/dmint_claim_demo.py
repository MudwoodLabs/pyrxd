#!/usr/bin/env python3
"""Mint a token from an existing V1 dMint contract on Radiant mainnet.

This is the "claim from RBG (or any V1 dMint contract)" flow. Unlike
``ft_transfer_demo.py`` (which sends FT tokens you already own) and
``ft_deploy_premine.py`` (which issues a fresh premine FT), this script
spends a live dMint contract UTXO, mines a PoW solution, and produces a
mint transaction that pays the miner a freshly-emitted FT reward.

Why this example exists
-----------------------
``tests/test_dmint_v1_mint.py`` synthesises V1 contract UTXOs in-process
and exercises the full mint-tx assembly logic. Those tests prove the
math and structural shape are correct (including a byte-equal
golden-vector test against captured mainnet bytes). They cannot prove
that pyrxd's output gets accepted by the live network — only a
broadcast on mainnet does that.

This demo is the **manual acceptance gate** for Milestone 1 of the
dMint integration plan. Run it once with ``DRY_RUN=1`` to inspect the
unsigned tx, then with ``DRY_RUN=0`` plus ``I_UNDERSTAND_THIS_IS_REAL=yes``
to broadcast.

Caveats
-------
- **The PoW search takes a long time in pure Python.** At the live RBG
  difficulty (~2^32 expected attempts at the leading-zero floor),
  expect tens of minutes to hours single-threaded. Set ``EXTERNAL_MINER``
  to delegate to glyph-miner or another fast miner.
- **The contract may advance under you.** Between the time you query
  the contract state and the time you broadcast, another miner may
  claim the height you were targeting. The script will print the
  rejection reason from the network and exit; you re-run.
- **You need a funded plain-RXD address.** The contract is a singleton
  (1 photon); the miner pays the FT reward carrier value (50,000 photons
  for RBG) plus the tx fee from a separate funding input.

Usage
-----
::

    # Dry-run (mines, builds, prints raw hex, does NOT broadcast):
    MINER_WIF=<wif> \\
    CONTRACT_TXID=<txid> CONTRACT_VOUT=<n> \\
    python examples/dmint_claim_demo.py

    # Real broadcast (only after a clean dry-run):
    DRY_RUN=0 I_UNDERSTAND_THIS_IS_REAL=yes \\
    MINER_WIF=<wif> \\
    CONTRACT_TXID=<txid> CONTRACT_VOUT=<n> \\
    python examples/dmint_claim_demo.py

Find the current contract UTXO out-of-band (via a Radiant block
explorer); pyrxd does not yet ship a chain walker for the dMint
contract chain (M2 work).

Environment
-----------
    MINER_WIF              WIF private key for funding + reward (required)
    CONTRACT_TXID          txid of the live contract UTXO (required)
    CONTRACT_VOUT          output index of the contract UTXO (required)
    DRY_RUN                Default ``1``; ``0`` = build+broadcast
    I_UNDERSTAND_THIS_IS_REAL  Required when DRY_RUN=0; must equal "yes"
    ELECTRUMX_URL          WebSocket URL (default: radiant4people mainnet)
    FEE_RATE               photons/byte (default: 10000)
    OP_RETURN_MSG          optional ASCII msg to embed in vout[2] (≤80 bytes)
    MAX_ATTEMPTS           cap on the Python miner's nonce sweep
                           (default: pyrxd.glyph.dmint.DEFAULT_MAX_ATTEMPTS)
    EXTERNAL_MINER         optional argv (space-separated) for a subprocess miner
                           e.g. ``glyph-miner --stdin`` — receives JSON on stdin
                           with preimage_hex/target_hex/nonce_width and returns
                           ``{"nonce_hex": "..."}`` on stdout

Funding-UTXO selection
----------------------
The miner's wallet must hold at least one plain-RXD UTXO large enough
to cover ``state.reward + estimated_fee + dust``. The script scans
the wallet's UTXOs, **excludes any token-bearing UTXOs** (FTs, NFTs,
dMint contracts) using the same opcode-aware walker the library uses
to defend against silent token-burn, and picks the largest qualifying
candidate.

If the wallet has no plain-RXD UTXOs (or all of them are too small),
the script raises :class:`InvalidFundingUtxoError` and exits.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pyrxd.glyph.dmint import (
    DEFAULT_MAX_ATTEMPTS,
    DmintContractUtxo,
    DmintState,
    build_dmint_mint_tx,
    build_dmint_v1_mint_preimage,
    build_mint_scriptsig,
    find_dmint_funding_utxo,
    mine_solution,
    mine_solution_external,
)
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata
from pyrxd.security.errors import (
    ContractExhaustedError,
    InvalidFundingUtxoError,
    MaxAttemptsError,
    NetworkError,
    PoolTooSmallError,
    ValidationError,
)
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DRY_RUN: bool = os.environ.get("DRY_RUN", "1") != "0"
I_UNDERSTAND_THIS_IS_REAL: str = os.environ.get("I_UNDERSTAND_THIS_IS_REAL", "")
ELECTRUMX_URL: str = os.environ.get("ELECTRUMX_URL", "wss://electrumx.radiant4people.com:50022/")
MINER_WIF: str = os.environ.get("MINER_WIF", "")
CONTRACT_TXID: str = os.environ.get("CONTRACT_TXID", "")
CONTRACT_VOUT: str = os.environ.get("CONTRACT_VOUT", "")
FEE_RATE: int = int(os.environ.get("FEE_RATE", "10000"))
OP_RETURN_MSG: str = os.environ.get("OP_RETURN_MSG", "")
MAX_ATTEMPTS: int = int(os.environ.get("MAX_ATTEMPTS", str(DEFAULT_MAX_ATTEMPTS)))
EXTERNAL_MINER: str = os.environ.get("EXTERNAL_MINER", "")

# Standard relay-policy dust floor (matches build_dmint_mint_tx's check).
_DUST_LIMIT = 546


# ---------------------------------------------------------------------------
# Contract-UTXO fetch
# ---------------------------------------------------------------------------


async def _fetch_contract_utxo(
    client: ElectrumXClient,
    txid: str,
    vout: int,
) -> DmintContractUtxo:
    """Fetch the contract output at ``txid:vout`` and parse its dMint state.

    Raises :class:`ValidationError` if the output is not a dMint contract.
    """
    tx_bytes = await client.get_transaction(Txid(txid))
    tx = Transaction.from_hex(bytes(tx_bytes))
    if tx is None or vout >= len(tx.outputs):
        raise ValidationError(f"contract output {txid}:{vout} not found in fetched tx")
    out = tx.outputs[vout]
    script = out.locking_script.serialize()
    state = DmintState.from_script(script)
    return DmintContractUtxo(
        txid=txid,
        vout=vout,
        value=out.satoshis,
        script=script,
        state=state,
    )


# ---------------------------------------------------------------------------
# Funding-input signing (P2PKH)
# ---------------------------------------------------------------------------


def _sign_p2pkh_input(tx: Transaction, input_index: int, private_key: PrivateKey) -> None:
    """Attach a standard P2PKH unlocking script to ``tx.inputs[input_index]``.

    The contract input (vin[0]) is already populated with the placeholder
    ``build_mint_scriptsig`` output; this helper signs the funding input
    (vin[1]) using the miner's WIF.
    """
    sig = private_key.sign(tx.preimage(input_index))
    sighash = tx.inputs[input_index].sighash
    pub = private_key.public_key().serialize()
    unlock = encode_pushdata(sig + sighash.to_bytes(1, "little")) + encode_pushdata(pub)
    tx.inputs[input_index].unlocking_script = Script(unlock)


# ---------------------------------------------------------------------------
# Mine
# ---------------------------------------------------------------------------


def _mine(preimage: bytes, target: int, nonce_width: int) -> bytes:
    """Find a nonce satisfying the target. Uses an external miner if
    ``EXTERNAL_MINER`` is set, otherwise the slow Python reference."""
    if EXTERNAL_MINER:
        argv = shlex.split(EXTERNAL_MINER)
        print(f"Mining via external miner: {argv[0]}")
        result = mine_solution_external(
            preimage=preimage,
            target=target,
            miner_argv=argv,
            nonce_width=nonce_width,  # type: ignore[arg-type]
        )
    else:
        print(
            f"Mining in pure Python (slow). MAX_ATTEMPTS={MAX_ATTEMPTS:_}. "
            f"Set EXTERNAL_MINER to use a fast external miner."
        )
        result = mine_solution(
            preimage=preimage,
            target=target,
            nonce_width=nonce_width,  # type: ignore[arg-type]
            max_attempts=MAX_ATTEMPTS,
        )
    print(f"Found nonce {result.nonce.hex()} after {result.attempts:,} attempts in {result.elapsed_s:.1f}s")
    return result.nonce


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    if not MINER_WIF:
        print("ERROR: set MINER_WIF to your funded WIF private key", file=sys.stderr)
        sys.exit(1)
    if not CONTRACT_TXID:
        print("ERROR: set CONTRACT_TXID to the live contract UTXO txid", file=sys.stderr)
        sys.exit(1)
    if not CONTRACT_VOUT:
        print("ERROR: set CONTRACT_VOUT to the contract UTXO output index", file=sys.stderr)
        sys.exit(1)

    if not DRY_RUN and I_UNDERSTAND_THIS_IS_REAL != "yes":
        print(
            "ERROR: DRY_RUN=0 requires I_UNDERSTAND_THIS_IS_REAL=yes (broadcasts a "
            "real mainnet tx that costs RXD and is irreversible)",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        miner_key = PrivateKey(MINER_WIF)
    except Exception:
        print("ERROR: MINER_WIF could not be decoded as a WIF private key", file=sys.stderr)
        sys.exit(1)
    miner_address = miner_key.public_key().address()
    miner_pkh = bytes(Hex20(miner_key.public_key().hash160()))
    contract_vout = int(CONTRACT_VOUT)
    # Default to an OP_RETURN msg matching observed mainnet behavior.
    # Every mint tx traced in docs/dmint-research-mainnet.md §4 includes a
    # `msg`-marker OP_RETURN at vout[2]; the V1 covenant binds outputHash
    # to that script, so omitting it would change the preimage shape
    # (and likely cause a covenant rejection, though this is unverified).
    # Users who want to experiment can set OP_RETURN_MSG=NONE.
    if OP_RETURN_MSG.upper() == "NONE":
        op_return_msg = None
    elif OP_RETURN_MSG:
        op_return_msg = OP_RETURN_MSG.encode("utf-8")
    else:
        op_return_msg = b"pyrxd-mint"  # short default — keeps tx within standardness

    print(f"Miner:           {miner_address}")
    print(f"Contract UTXO:   {CONTRACT_TXID}:{contract_vout}")
    print(f"Fee rate:        {FEE_RATE} photons/byte")
    print(f"DRY_RUN:         {DRY_RUN}")
    if op_return_msg:
        print(f"OP_RETURN msg:   {op_return_msg!r}")
    print()

    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        # 1. Fetch contract UTXO
        print("Fetching contract UTXO...")
        try:
            contract_utxo = await _fetch_contract_utxo(client, CONTRACT_TXID, contract_vout)
        except (NetworkError, ValidationError) as exc:
            print(f"ERROR: could not fetch/parse contract UTXO: {exc}", file=sys.stderr)
            sys.exit(2)
        state = contract_utxo.state
        print(
            f"  height:  {state.height:,} of {state.max_height:,} ({100 * state.height / state.max_height:.2f}% mined)"
        )
        print(f"  reward:  {state.reward:,} photons (= base units of FT)")
        print(f"  is_v1:   {state.is_v1}")
        if not state.is_v1:
            print(
                "ERROR: this demo only handles V1 dMint contracts; the supplied UTXO is V2",
                file=sys.stderr,
            )
            sys.exit(2)
        if state.is_exhausted:
            print(
                f"ERROR: contract is exhausted (height={state.height} >= max_height={state.max_height})",
                file=sys.stderr,
            )
            sys.exit(2)

        # 2. Funding-UTXO scan. Conservative bound: reward + ~10MB of fee.
        #    The actual fee is computed by build_dmint_mint_tx; this number
        #    just guarantees the funding UTXO has enough headroom.
        needed = state.reward + 10_000_000 + _DUST_LIMIT
        print(f"\nScanning {miner_address} for plain-RXD funding UTXO (≥ {needed:,} photons)...")
        try:
            funding_utxo = await find_dmint_funding_utxo(client, miner_address, needed)
        except InvalidFundingUtxoError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(2)
        print(f"  funding: {funding_utxo.txid}:{funding_utxo.vout} ({funding_utxo.value:,} photons)")

        # 3. Build unsigned tx with placeholder preimage. The nonce is the
        #    placeholder zero — `build_dmint_mint_tx` only validates length.
        placeholder_nonce = b"\x00" * 4
        try:
            result = build_dmint_mint_tx(
                contract_utxo=contract_utxo,
                nonce=placeholder_nonce,
                miner_pkh=miner_pkh,
                current_time=0,  # V1 has no DAA; explicit no-op
                fee_rate=FEE_RATE,
                funding_utxo=funding_utxo,
                op_return_msg=op_return_msg,
            )
        except (ContractExhaustedError, PoolTooSmallError, ValidationError) as exc:
            print(f"ERROR: build_dmint_mint_tx refused: {exc}", file=sys.stderr)
            sys.exit(2)
        print(
            f"\nUnsigned tx built (fee: {result.fee:,} photons, "
            f"{len(result.tx.inputs)} inputs, {len(result.tx.outputs)} outputs)"
        )

        # 4. Compute real preimage from the now-finalised tx outputs.
        preimage = build_dmint_v1_mint_preimage(contract_utxo, funding_utxo, result.tx)

        # 5. Mine.
        try:
            nonce = _mine(preimage, state.target, nonce_width=4)
        except MaxAttemptsError as exc:
            print(
                f"\nERROR: miner exhausted {exc.attempts:,} attempts in {exc.elapsed_s:.1f}s "
                "without finding a solution. Re-run with a higher MAX_ATTEMPTS, or set "
                "EXTERNAL_MINER to delegate to glyph-miner.",
                file=sys.stderr,
            )
            sys.exit(2)

        # 6. Splice the real nonce + real preimage into the contract input's scriptSig.
        real_scriptsig = build_mint_scriptsig(nonce, preimage, nonce_width=4)
        result.tx.inputs[0].unlocking_script = Script(real_scriptsig)

        # 7. Sign the funding input.
        _sign_p2pkh_input(result.tx, 1, miner_key)

        # 8. Print final tx state.
        print(f"\nFinal tx: {result.tx.txid()}")
        print(f"  size:   {result.tx.byte_length()} bytes")
        print(f"  fee:    {result.fee:,} photons")
        print(f"  inputs: {len(result.tx.inputs)}")
        print("  outputs:")
        for i, out in enumerate(result.tx.outputs):
            kind = {0: "contract", 1: "FT reward"}.get(i, f"vout[{i}]")
            print(f"    [{i}] {out.satoshis:>15,} photons  ({kind})")
        print()

        if DRY_RUN:
            print("[DRY RUN] Tx not broadcast. Set DRY_RUN=0 (with I_UNDERSTAND_THIS_IS_REAL=yes) to broadcast.")
            print()
            print(f"Raw tx hex:\n{result.tx.hex()}")
            return

        print("Broadcasting...")
        try:
            txid = await client.broadcast(result.tx.serialize())
        except NetworkError as exc:
            print(f"\nBROADCAST FAILED: {exc}", file=sys.stderr)
            print(
                "\nMost likely the contract advanced under you (someone else claimed "
                "this height first). Re-run the script — it will fetch the new contract "
                "tip and re-mine.",
                file=sys.stderr,
            )
            sys.exit(3)
        print(f"\n✓ Broadcast result: {txid}")
        print(
            "\nCongratulations. You just minted from a live dMint contract via pyrxd. "
            "The mint will confirm in the next block; check your wallet for the FT reward."
        )


if __name__ == "__main__":
    asyncio.run(main())
