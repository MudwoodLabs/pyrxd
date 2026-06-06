"""Inline mainnet Glyph-NFT mint + singleton→covenant lock for the ETH↔RXD swap runner.

This is the MAINNET adaptation of the proven regtest flow in
``tests/test_xchain_eth_glyph_real_rxindexer_e2e.py`` (``_mint_glyph`` +
``_spend_singleton_into_covenant``). Two differences, both because this moves REAL
mainnet value:

  * **No mining.** Regtest mines on demand; mainnet does not — every broadcast is
    followed by a real-confirmation WAIT (poll ``getrawtransaction`` until
    confirmations >= 1) before the next tx (which spends it) is built.
  * **Confirm-before-broadcast.** Each of the (up to) three broadcasts — commit,
    reveal, singleton-lock — pauses for an explicit operator y/N via ``confirm_fn``.

Broadcasts + wallet reads go through the live ``SshTrRadiantClient`` (``radiant-cli``
over ssh). The small tx-building helpers are replicated from the proven test (NOT
imported — test code must not be a script dependency).

Fees: mainnet relayfee is 0.10 RXD/kB; these txs are sub-kB, so ``fee_photons`` (default
0.05 RXD) covers them with margin. The operator accepts the dust overpay.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# Defaults (photons). commit funds the reveal fee + the singleton carrier; sized so
# reveal_value and the lock carrier stay positive at the mainnet fee.
DEFAULT_COMMIT_PHOTONS = 20_000_000  # 0.20 RXD
DEFAULT_FEE_PHOTONS = 5_000_000  # 0.05 RXD per sub-kB tx (mainnet 0.10 RXD/kB, margin)


@dataclass(frozen=True)
class MintedNft:
    """A genuinely-minted NFT singleton.

    Radiant identifies a singleton by its IMMUTABLE genesis ref — the outpoint the reveal SPENT to
    mint it (here ``commit_txid:0``), embedded in the singleton script via ``OP_PUSHINPUTREFSINGLETON``
    (``d8<ref>``). That ref — NOT ``reveal_txid:0`` (the singleton's current *location*) — is what the
    covenant binds and the indexer/REF gate resolves. ``reveal_txid`` is kept only as the spend source
    for the lock tx (the UTXO the singleton currently sits on)."""

    ref_str: str  # "<genesis_txid>:<genesis_vout>" — the true genesis ref (commit outpoint)
    reveal_txid: str  # where the singleton currently sits (the lock tx spends reveal_txid:0)
    genesis_txid: str  # display-order txid of the genesis ref the singleton carries (commit outpoint)
    genesis_vout: int
    owner_key: PrivateKey
    locking_script: bytes
    reveal_value: int


def _genesis_ref_from_singleton(locking_script: bytes) -> tuple[str, int]:
    """Parse the genesis ref the minted singleton actually carries (ground truth, not assumed).

    A Radiant Glyph singleton begins ``OP_PUSHINPUTREFSINGLETON(0xd8) <36-byte ref> OP_DROP(0x75) …``
    where ref = txid(32, internal/LE) ++ vout(4, LE). The token is identified by THIS ref (the outpoint
    the reveal spent to mint it = the commit outpoint), not by where the singleton happens to sit now."""
    if len(locking_script) < 37 or locking_script[0] != 0xD8:
        raise RuntimeError(f"minted singleton does not start with d8<ref36>: {locking_script[:8].hex()}")
    ref = locking_script[1:37]
    return ref[:32][::-1].hex(), int.from_bytes(ref[32:36], "little")


def _src(txid: str, vout: int, spk: bytes, val: int) -> Transaction:
    outs = [TransactionOutput(Script(b"\x00"), 0) for _ in range(vout)]
    outs.append(TransactionOutput(Script(spk), val))
    t = Transaction(tx_inputs=[], tx_outputs=outs)
    t.txid = lambda: txid  # type: ignore[method-assign]
    return t


def _p2pkh_unlock(key: PrivateKey):
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        return Script(
            encode_pushdata(key.sign(tx.preimage(idx)) + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub)
        )

    return to_unlock_script_template(_u, lambda: 110)


def _glyph_unlock(key: PrivateKey, suffix: bytes):
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        p2pkh = encode_pushdata(key.sign(tx.preimage(idx)) + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub)
        return Script(p2pkh + suffix)

    return to_unlock_script_template(_u, lambda: 200)


def _p2pkh_spk(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"


def _cli(rxd_client, *args: str):
    """One radiant-cli call over ssh (parsed JSON / scalar)."""
    return rxd_client._run_sync(*args)


def _largest_wallet_utxo(rxd_client, min_photons: int) -> dict:
    utxos = [u for u in _cli(rxd_client, "listunspent", "1", "9999999") if round(u["amount"] * 1e8) >= min_photons]
    if not utxos:
        raise RuntimeError(f"no mainnet wallet UTXO >= {min_photons} photons (~{min_photons / 1e8:.4f} RXD) to fund the mint")
    return max(utxos, key=lambda x: x["amount"])


def _wait_confirmed(rxd_client, txid: str, *, label: str, poll_s: float, log: Callable[[str], None]) -> None:
    """Block until ``txid`` has >= 1 mainnet confirmation (no mining on mainnet)."""
    log(f"    waiting for {label} ({txid}) to confirm on mainnet (poll {poll_s:.0f}s)…")
    while True:
        try:
            v = _cli(rxd_client, "getrawtransaction", txid, "1")
            confs = v.get("confirmations", 0) if isinstance(v, dict) else 0
            if isinstance(confs, int) and confs >= 1:
                log(f"    {label} confirmed ({confs} conf).")
                return
        except Exception:  # not yet in a block / mempool-only → keep polling
            pass
        time.sleep(poll_s)


def load_minted_nft(rxd_client, *, reveal_txid: str, owner_wif: str) -> MintedNft:
    """Reconstruct a :class:`MintedNft` for an ALREADY-minted NFT (skip the mint), e.g. to resume a
    run that aborted after minting. Fetches the reveal tx on-chain for the singleton script + carrier
    value, parses the true genesis ref from the singleton's ``d8`` opcode, and binds the owner key.

    Safety: asserts the owner key's hash160 equals the p2pkh inside the singleton — i.e. this key can
    actually spend the singleton into the covenant (a wrong key would fail to lock the asset)."""
    v = _cli(rxd_client, "getrawtransaction", reveal_txid, "1")
    if not isinstance(v, dict) or not v.get("vout"):
        raise RuntimeError(f"reuse: reveal tx {reveal_txid} not found / has no outputs")
    out0 = v["vout"][0]
    locking_script = bytes.fromhex(out0["scriptPubKey"]["hex"])
    reveal_value = round(float(out0["value"]) * 1e8)
    g_txid, g_vout = _genesis_ref_from_singleton(locking_script)
    key = PrivateKey(str(owner_wif))
    # singleton spk = d8 <ref36> 75 76 a9 14 <pkh20> 88 ac  -> pkh at offset 41:61
    spk_pkh = locking_script[41:61]
    if spk_pkh != bytes(key.public_key().hash160()):
        raise RuntimeError("reuse: owner WIF does not match the singleton's p2pkh — wrong key, cannot spend the NFT")
    return MintedNft(
        ref_str=f"{g_txid}:{g_vout}",
        reveal_txid=reveal_txid,
        genesis_txid=g_txid,
        genesis_vout=g_vout,
        owner_key=key,
        locking_script=locking_script,
        reveal_value=reveal_value,
    )


def wait_genesis_mature(
    rxd_client, genesis_txid: str, *, need_confs: int, poll_s: float, log: Callable[[str], None] = print
) -> None:
    """Block until the NFT genesis tx reaches ``need_confs`` confirmations (the REF-gate depth).

    The pre-lock gate fails closed on a shallow genesis — a reorg could void the NFT's provenance
    AFTER the counter-leg is paid — so the harness must wait for genesis maturity before funding."""
    log(f"    waiting for NFT genesis {genesis_txid} to reach {need_confs} confs (REF-gate reorg depth)…")
    while True:
        try:
            v = _cli(rxd_client, "getrawtransaction", genesis_txid, "1")
            c = v.get("confirmations", 0) if isinstance(v, dict) else 0
            if isinstance(c, int) and c >= need_confs:
                log(f"    genesis mature ({c} confs >= {need_confs}).")
                return
            log(f"    genesis at {c}/{need_confs} confs; waiting {poll_s:.0f}s…")
        except Exception:
            pass
        time.sleep(poll_s)


def mint_nft_inline(
    rxd_client,
    *,
    name: str,
    commit_photons: int = DEFAULT_COMMIT_PHOTONS,
    fee_photons: int = DEFAULT_FEE_PHOTONS,
    confirm_fn: Callable[[str], None],
    poll_s: float = 30.0,
    log: Callable[[str], None] = print,
) -> MintedNft:
    """Mint a throwaway NFT on Radiant mainnet (commit→reveal). Genesis ref = ``reveal_txid:0``.

    Pauses for operator confirmation before EACH broadcast and waits for real confirmation
    between the commit and the reveal (the reveal spends the commit output)."""
    if commit_photons <= 2 * fee_photons:
        raise RuntimeError("commit_photons must exceed 2*fee_photons (reveal + lock both pay a fee)")
    builder = GlyphBuilder()
    u = _largest_wallet_utxo(rxd_client, commit_photons + 2 * fee_photons)
    key = PrivateKey(str(_cli(rxd_client, "dumpprivkey", u["address"])))
    pkh = Hex20(key.public_key().hash160())
    spk = bytes.fromhex(u["scriptPubKey"])
    in_sats = round(u["amount"] * 1e8)

    meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name, token_type="object")  # noqa: S106 (glyph token kind, not a secret)
    commit = builder.prepare_commit(CommitParams(metadata=meta, owner_pkh=pkh, change_pkh=pkh, funding_satoshis=in_sats))

    fin = TransactionInput(
        source_transaction=_src(u["txid"], int(u["vout"]), spk, in_sats),
        source_txid=u["txid"],
        source_output_index=int(u["vout"]),
        unlocking_script_template=_p2pkh_unlock(key),
    )
    fin.satoshis = in_sats
    fin.locking_script = Script(spk)
    commit_tx = Transaction(
        tx_inputs=[fin],
        tx_outputs=[
            TransactionOutput(Script(commit.commit_script), commit_photons),
            TransactionOutput(Script(_p2pkh_spk(pkh)), in_sats - commit_photons - fee_photons),
        ],
    )
    commit_tx.sign()
    confirm_fn(f"mint step 1/2: broadcast the NFT COMMIT tx on mainnet ({commit_photons / 1e8:.4f} RXD into the commit output)")
    commit_txid = str(_cli(rxd_client, "sendrawtransaction", commit_tx.serialize().hex()))
    log(f"    commit -> {commit_txid}")
    _wait_confirmed(rxd_client, commit_txid, label="commit", poll_s=poll_s, log=log)

    rev = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=commit_photons,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=pkh,
            is_nft=True,
        )
    )
    rin = TransactionInput(
        source_transaction=_src(commit_txid, 0, commit.commit_script, commit_photons),
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=_glyph_unlock(key, rev.scriptsig_suffix),
    )
    rin.satoshis = commit_photons
    rin.locking_script = Script(commit.commit_script)
    reveal_value = commit_photons - fee_photons
    reveal_tx = Transaction(tx_inputs=[rin], tx_outputs=[TransactionOutput(Script(rev.locking_script), reveal_value)])
    reveal_tx.sign()
    confirm_fn(f"mint step 2/2: broadcast the NFT REVEAL tx (creates the singleton at reveal_txid:0, carrier {reveal_value / 1e8:.4f} RXD)")
    reveal_txid = str(_cli(rxd_client, "sendrawtransaction", reveal_tx.serialize().hex()))
    # The genesis ref is the COMMIT outpoint the singleton carries (d8<ref>), NOT reveal_txid:0.
    g_txid, g_vout = _genesis_ref_from_singleton(rev.locking_script)
    log(f"    reveal -> {reveal_txid}  (singleton at reveal:0; genesis ref = {g_txid}:{g_vout} [the commit outpoint])")
    _wait_confirmed(rxd_client, reveal_txid, label="reveal", poll_s=poll_s, log=log)
    return MintedNft(
        ref_str=f"{g_txid}:{g_vout}",
        reveal_txid=reveal_txid,
        genesis_txid=g_txid,
        genesis_vout=g_vout,
        owner_key=key,
        locking_script=rev.locking_script,
        reveal_value=reveal_value,
    )


def lock_singleton_into_covenant(
    rxd_client,
    *,
    minted: MintedNft,
    covenant_spk: bytes,
    carrier_photons: int,
    fee_photons: int = DEFAULT_FEE_PHOTONS,
    confirm_fn: Callable[[str], None],
    poll_s: float = 30.0,
    log: Callable[[str], None] = print,
) -> str:
    """Spend the minted NFT singleton (``reveal_txid:0``) into the covenant SPK — the maker's
    'lock the asset' step. Single input (NFT carries enough); change returns to the owner so
    we don't overpay the fee into the void. Confirms before broadcast + waits for confirmation."""
    if not (0 < carrier_photons <= minted.reveal_value - fee_photons):
        raise RuntimeError("carrier_photons must be in (0, reveal_value - fee]")
    rin = TransactionInput(
        source_transaction=_src(minted.reveal_txid, 0, minted.locking_script, minted.reveal_value),
        source_txid=minted.reveal_txid,
        source_output_index=0,
        unlocking_script_template=_p2pkh_unlock(minted.owner_key),
    )
    rin.satoshis = minted.reveal_value
    rin.locking_script = Script(minted.locking_script)
    outs = [TransactionOutput(Script(covenant_spk), carrier_photons)]
    change = minted.reveal_value - carrier_photons - fee_photons
    if change > 0:  # return the excess to the owner rather than burn it as fee
        outs.append(TransactionOutput(Script(_p2pkh_spk(minted.owner_key.public_key().hash160())), change))
    tx = Transaction(tx_inputs=[rin], tx_outputs=outs)
    tx.sign()
    confirm_fn(f"lock the NFT singleton into the covenant SPK on mainnet (carrier {carrier_photons / 1e8:.4f} RXD)")
    txid = str(_cli(rxd_client, "sendrawtransaction", tx.serialize().hex()))
    log(f"    asset lock -> {txid}")
    _wait_confirmed(rxd_client, txid, label="asset-lock", poll_s=poll_s, log=log)
    return txid


# --------------------------------------------------------------------------- FT (fungible token)


@dataclass(frozen=True)
class MintedFt:
    """A genuinely-minted Glyph FT (full premine in one holder UTXO).

    Like the NFT, the FT's identity is its IMMUTABLE genesis ref — the COMMIT outpoint carried in the
    holder script's ``bd d0 <ref>`` (NOT the reveal txid). ``ft_amount`` photons = FT units (consensus:
    1 photon = 1 unit). ``reveal_txid`` is where the premine holder currently sits (the lock spends it)."""

    ref_str: str  # "<genesis_txid>:<genesis_vout>" — the true genesis ref (commit outpoint)
    reveal_txid: str  # where the FT premine holder currently sits (the lock spends reveal_txid:0)
    genesis_txid: str
    genesis_vout: int
    owner_key: PrivateKey
    ft_script: bytes  # the 75-byte FT holder script (p2pkh + bd d0 <ref> + epilogue)
    ft_amount: int  # premine photons == FT units


def _genesis_ref_from_ft_script(ft_script: bytes) -> tuple[str, int]:
    """Parse the genesis ref an FT holder script carries (ground truth, not assumed).

    FT holder = ``76a914<pkh:20>88ac bd d0 <ref:36> <epilogue:12>`` (75 bytes). The ref (= the COMMIT
    outpoint the FT was minted at, persists across transfers) sits at offset 27, after the 25-byte
    p2pkh prologue + ``bd d0``."""
    if len(ft_script) != 75 or ft_script[25] != 0xBD or ft_script[26] != 0xD0:
        raise RuntimeError(f"not a 75-byte FT holder script (expect bd d0 at 25): {ft_script[:8].hex()}")
    ref = ft_script[27:63]
    return ref[:32][::-1].hex(), int.from_bytes(ref[32:36], "little")


def mint_ft_inline(
    rxd_client,
    *,
    name: str,
    ticker: str = "",
    premine_amount: int,
    fee_photons: int = DEFAULT_FEE_PHOTONS,
    confirm_fn: Callable[[str], None],
    poll_s: float = 30.0,
    log: Callable[[str], None] = print,
) -> MintedFt:
    """Mint a throwaway Glyph FT on Radiant mainnet (commit→reveal premine). Genesis ref = the COMMIT
    outpoint the holder's ``bd d0 <ref>`` carries. The reveal output holds ``premine_amount`` photons
    (= FT units). Pauses for operator confirmation before EACH broadcast + waits for confirmation."""
    if premine_amount <= 0:
        raise RuntimeError("premine_amount must be positive")
    # commit funds the reveal: the reveal spends the commit -> ONE FT output (premine), leftover = fee.
    commit_photons = premine_amount + fee_photons
    builder = GlyphBuilder()
    u = _largest_wallet_utxo(rxd_client, commit_photons + 2 * fee_photons)
    key = PrivateKey(str(_cli(rxd_client, "dumpprivkey", u["address"])))
    pkh = Hex20(key.public_key().hash160())
    spk = bytes.fromhex(u["scriptPubKey"])
    in_sats = round(u["amount"] * 1e8)

    meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name=name, ticker=ticker)
    commit = builder.prepare_commit(CommitParams(metadata=meta, owner_pkh=pkh, change_pkh=pkh, funding_satoshis=in_sats))
    fin = TransactionInput(
        source_transaction=_src(u["txid"], int(u["vout"]), spk, in_sats),
        source_txid=u["txid"],
        source_output_index=int(u["vout"]),
        unlocking_script_template=_p2pkh_unlock(key),
    )
    fin.satoshis = in_sats
    fin.locking_script = Script(spk)
    commit_tx = Transaction(
        tx_inputs=[fin],
        tx_outputs=[
            TransactionOutput(Script(commit.commit_script), commit_photons),
            TransactionOutput(Script(_p2pkh_spk(pkh)), in_sats - commit_photons - fee_photons),
        ],
    )
    commit_tx.sign()
    confirm_fn(f"FT mint step 1/2: broadcast the COMMIT tx on mainnet ({commit_photons / 1e8:.4f} RXD into the commit output)")
    commit_txid = str(_cli(rxd_client, "sendrawtransaction", commit_tx.serialize().hex()))
    log(f"    commit -> {commit_txid}")
    _wait_confirmed(rxd_client, commit_txid, label="commit", poll_s=poll_s, log=log)

    rev = builder.prepare_ft_deploy_reveal(
        commit_txid=commit_txid,
        commit_vout=0,
        commit_value=commit_photons,
        cbor_bytes=commit.cbor_bytes,
        premine_pkh=pkh,
        premine_amount=premine_amount,
    )
    rin = TransactionInput(
        source_transaction=_src(commit_txid, 0, commit.commit_script, commit_photons),
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=_glyph_unlock(key, rev.scriptsig_suffix),
    )
    rin.satoshis = commit_photons
    rin.locking_script = Script(commit.commit_script)
    # ONE FT output (premine); the commit leftover (commit_photons - premine = fee_photons) is the fee.
    reveal_tx = Transaction(
        tx_inputs=[rin], tx_outputs=[TransactionOutput(Script(rev.locking_script), premine_amount)]
    )
    reveal_tx.sign()
    g_txid, g_vout = _genesis_ref_from_ft_script(rev.locking_script)
    confirm_fn(f"FT mint step 2/2: broadcast the REVEAL tx (premines {premine_amount} FT units at reveal:0)")
    reveal_txid = str(_cli(rxd_client, "sendrawtransaction", reveal_tx.serialize().hex()))
    log(f"    reveal -> {reveal_txid}  (FT premine at reveal:0; genesis ref = {g_txid}:{g_vout} [the commit outpoint])")
    _wait_confirmed(rxd_client, reveal_txid, label="reveal", poll_s=poll_s, log=log)
    return MintedFt(
        ref_str=f"{g_txid}:{g_vout}",
        reveal_txid=reveal_txid,
        genesis_txid=g_txid,
        genesis_vout=g_vout,
        owner_key=key,
        ft_script=rev.locking_script,
        ft_amount=premine_amount,
    )


def load_minted_ft(rxd_client, *, reveal_txid: str, owner_wif: str) -> MintedFt:
    """Reconstruct a :class:`MintedFt` for an ALREADY-minted FT (skip the mint), e.g. to resume a run
    that aborted after minting. Fetches the reveal tx on-chain for the FT holder script + amount,
    parses the genesis ref from the holder's ``bd d0 <ref>``, and binds the owner key.

    Safety: asserts the owner key's hash160 equals the p2pkh inside the FT holder — i.e. this key can
    actually spend the FT into the covenant."""
    v = _cli(rxd_client, "getrawtransaction", reveal_txid, "1")
    if not isinstance(v, dict) or not v.get("vout"):
        raise RuntimeError(f"reuse: FT reveal tx {reveal_txid} not found / has no outputs")
    out0 = v["vout"][0]
    ft_script = bytes.fromhex(out0["scriptPubKey"]["hex"])
    ft_amount = round(float(out0["value"]) * 1e8)
    g_txid, g_vout = _genesis_ref_from_ft_script(ft_script)
    key = PrivateKey(str(owner_wif))
    # FT holder = 76 a9 14 <pkh:20> 88 ac ... -> pkh at offset 3:23
    if ft_script[3:23] != bytes(key.public_key().hash160()):
        raise RuntimeError("reuse: owner WIF does not match the FT holder's p2pkh — wrong key, cannot spend the FT")
    return MintedFt(
        ref_str=f"{g_txid}:{g_vout}",
        reveal_txid=reveal_txid,
        genesis_txid=g_txid,
        genesis_vout=g_vout,
        owner_key=key,
        ft_script=ft_script,
        ft_amount=ft_amount,
    )


def lock_ft_into_covenant(
    rxd_client,
    *,
    minted: MintedFt,
    covenant_spk: bytes,
    fee_photons: int = DEFAULT_FEE_PHOTONS,
    confirm_fn: Callable[[str], None],
    poll_s: float = 30.0,
    log: Callable[[str], None] = print,
) -> str:
    """Lock the minted FT into the covenant SPK — the maker's 'lock the asset' step.

    FT conservation: the FT photons (= amount) must flow WHOLE into the covenant output, which shares
    the FT's ``codeScriptHash`` (same ``bd d0 <ref> epilogue``), so ``covenant out value == FT amount``.
    The miner fee CANNOT be skimmed off the FT value — it comes from a SEPARATE plain-RXD wallet input,
    with change back to the wallet. Confirms before broadcast + waits for confirmation."""
    # FT input (the premine holder) — spent via the owner's p2pkh prologue; the epilogue enforces
    # conservation against the covenant output at consensus time.
    fin = TransactionInput(
        source_transaction=_src(minted.reveal_txid, 0, minted.ft_script, minted.ft_amount),
        source_txid=minted.reveal_txid,
        source_output_index=0,
        unlocking_script_template=_p2pkh_unlock(minted.owner_key),
    )
    fin.satoshis = minted.ft_amount
    fin.locking_script = Script(minted.ft_script)
    # Separate plain-RXD fee input from the wallet (its surplus over the fee returns as change).
    fu = _largest_wallet_utxo(rxd_client, 2 * fee_photons)
    fkey = PrivateKey(str(_cli(rxd_client, "dumpprivkey", fu["address"])))
    fspk = bytes.fromhex(fu["scriptPubKey"])
    fee_in_sats = round(fu["amount"] * 1e8)
    feein = TransactionInput(
        source_transaction=_src(fu["txid"], int(fu["vout"]), fspk, fee_in_sats),
        source_txid=fu["txid"],
        source_output_index=int(fu["vout"]),
        unlocking_script_template=_p2pkh_unlock(fkey),
    )
    feein.satoshis = fee_in_sats
    feein.locking_script = Script(fspk)
    # Two-pass fee: the 2-input lock with a ~224B covenant output is ~600B — well above the sub-kB
    # mint txs — so a flat fee can fall UNDER the mainnet min-relay (0.10 RXD/kB = 10_000 photons/B).
    # Measure the signed size and pay >= size * rate with margin (the FT value flows whole regardless;
    # only the separate fee input + change absorb the fee).
    def _build(fee: int) -> Transaction:
        outs = [TransactionOutput(Script(covenant_spk), minted.ft_amount)]  # covenant carries the WHOLE FT amount
        ch = fee_in_sats - fee
        if ch > 0:
            outs.append(TransactionOutput(Script(_p2pkh_spk(fkey.public_key().hash160())), ch))
        fin.unlocking_script = None
        feein.unlocking_script = None
        t = Transaction(tx_inputs=[fin, feein], tx_outputs=outs)
        t.sign()
        return t

    fee = max(fee_photons, _build(fee_photons).byte_length() * 15_000)  # 1.5x the 10_000 photons/B relay floor
    tx = _build(fee)
    confirm_fn(f"lock the FT ({minted.ft_amount} units) into the covenant SPK on mainnet (fee {fee / 1e8:.4f} RXD from a separate input)")
    txid = str(_cli(rxd_client, "sendrawtransaction", tx.serialize().hex()))
    log(f"    FT asset lock -> {txid}")
    _wait_confirmed(rxd_client, txid, label="asset-lock", poll_s=poll_s, log=log)
    return txid
