"""END-TO-END ETH↔RXD atomic swap of a GENUINELY-MINTED Glyph NFT, authenticated by a REAL
RXinDexer (NOT the FakeIndexer / fake-singleton).

``test_xchain_eth_swap_regtest_e2e.py`` proves the swap MECHANISM, but its FT/NFT cases bind a
"fake singleton" (a plain wallet UTXO as the genesis ref, R1) and resolve it through a
``FakeIndexer`` that hands back a pre-built ``ResolvedRef``. That leaves two things unproven:

  1. A real ``GlyphBuilder`` commit→reveal mint actually produces a token RXinDexer indexes.
  2. ``RxinDexerRefAdapter`` correctly maps RXinDexer's REAL ``glyph.get_token`` dict (field names
     ``glyph_id`` / ``txid`` / ``vout``) to a ``ResolvedRef`` the pre-lock gate accepts.

This test closes both. It mints a real NFT Glyph (commit→reveal) on a running, RXinDexer-indexed
regtest node, binds the genuine genesis ref (``reveal_txid:0``) into the NFT HTLC covenant, spends
the real singleton into the covenant, and drives the whole ETH↔RXD swap through the mature
``SwapCoordinator`` with the REAL ``RxinDexerRefAdapter`` (over ws://) as the authenticity oracle.

Unlike the self-contained e2e (which spins up its own throwaway radiantd), this test requires a
pre-running RXinDexer stack indexing the node. It is therefore gated behind its own opt-in env var
and the explicit node/indexer endpoints. Moves no real value: regtest + local Anvil devnet keys.

Standing up the stack (one time):
  * rxd-regtest-node  — radiant-core:v3.1.1 regtest, RPC :17443, wallet ``gravity``
  * rxd-indexer       — rxindexer-electrumx:regtest (NET=regtest, DB_ENGINE=rocksdb, GLYPH_INDEX=1),
                        ElectrumX WS on 127.0.0.1:50011

Run it:
  XCHAIN_ETH_GLYPH_REAL=1 \
  RXD_NODE_CT=rxd-regtest-node RXD_RPCUSER=rxduser RXD_RPCPASS=rxdpass RXD_WALLET=gravity \
  RXINDEXER_WS=ws://127.0.0.1:50011 \
  pytest tests/test_xchain_eth_glyph_real_rxindexer_e2e.py -m integration -s
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import time

import pytest

pytest.importorskip("web3")
pytest.importorskip("eth_keys")

from pyrxd.btc_wallet import taproot as bt
from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.gravity.eth_leg import EthLeg
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_ft, build_htlc_covenant_nft
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg, RxinDexerRefAdapter
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.network.rxindexer import RxinDexerClient
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# tests.* is importable thanks to tests/conftest.py adding the repo root to sys.path (the
# console-script pytest only puts ``src`` on the path). Reuse the ETH e2e's anvil helpers + the
# recording leg + the in-mem seen store.
from tests.test_xchain_eth_swap_regtest_e2e import (
    _ADDR_MAKER,
    _ADDR_TAKER,
    _CHAIN_ID,
    _ETH_AMOUNT_WEI,
    _KEY,
    _anvil_mine,
    _anvil_now,
    _anvil_rpc,
    _free_port,
    _MemSeen,
    _RecordingEthLeg,
)

# Reuse the BTC e2e's Radiant-side helpers (no value moved; one source of truth).
from tests.test_xchain_swap_regtest_e2e import _RXD_RELAY_FEE, _FeeSource, _RadiantCliClient, _src

pytestmark = pytest.mark.integration

_ARTIFACT = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())
_COMMIT_VALUE = 5_000_000


# --------------------------------------------------------------------------- the running indexed node


class _IndexedNode:
    """A thin radiant-cli shim over an ALREADY-RUNNING, RXinDexer-indexed regtest node.

    Unlike ``_RxdNode`` (which spins up a throwaway container), this binds to the persistent node
    the RXinDexer is actually following, so a Glyph minted here is indexed and resolvable.
    """

    def __init__(self) -> None:
        self.ct = os.environ.get("RXD_NODE_CT", "rxd-regtest-node")
        self.user = os.environ.get("RXD_RPCUSER", "rxduser")
        self.pw = os.environ.get("RXD_RPCPASS", "rxdpass")
        self.wallet = os.environ.get("RXD_WALLET", "gravity")
        self.raddr = ""

    def rxd(self, *a, wallet="__default__"):
        w = self.wallet if wallet == "__default__" else wallet
        base = [
            "docker",
            "exec",
            self.ct,
            "radiant-cli",
            "-regtest",
            f"-rpcuser={self.user}",
            f"-rpcpassword={self.pw}",
        ]
        if w:
            base.append(f"-rpcwallet={w}")
        r = subprocess.run(base + list(a), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"radiant-cli {a[0]} failed: {r.stderr.strip()}")
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def rxd_mine(self, n=1):
        if not self.raddr:
            self.raddr = str(self.rxd("getnewaddress"))
        self.rxd("generatetoaddress", str(n), self.raddr)


def _p2pkh_unlock(key):
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        return Script(
            encode_pushdata(key.sign(tx.preimage(idx)) + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub)
        )

    return to_unlock_script_template(_u, lambda: 110)


def _glyph_unlock(key, suffix):
    pub = key.public_key().serialize()

    def _u(tx, idx):
        inp = tx.inputs[idx]
        p2pkh = encode_pushdata(key.sign(tx.preimage(idx)) + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub)
        return Script(p2pkh + suffix)

    return to_unlock_script_template(_u, lambda: 200)


def _largest_utxo(node, min_sats):
    utxos = [u for u in node.rxd("listunspent", "1") if round(u["amount"] * 1e8) >= min_sats]
    if not utxos:
        raise RuntimeError(f"no UTXO >= {min_sats} sats in wallet {node.wallet}")
    return max(utxos, key=lambda x: x["amount"])


class _Minted:
    """A genuinely-minted Glyph: genesis ref (``reveal_txid:0``) + the owner key + reveal output."""

    def __init__(self, ref_str, reveal_txid, owner_key, locking_script, reveal_value, is_nft):
        self.ref_str = ref_str
        self.reveal_txid = reveal_txid
        self.owner_key = owner_key
        self.locking_script = locking_script
        self.reveal_value = reveal_value
        self.is_nft = is_nft


def _mint_glyph(node, *, is_nft: bool) -> _Minted:
    """Mint a genuine NFT or FT Glyph (commit→reveal). The genesis ref is ``reveal_txid:0``.

    NFT: the reveal output is the ``d8 <ref> OP_DROP <p2pkh>`` singleton (small carrier value).
    FT:  the reveal output is the ``p2pkh + <conservation epilogue>`` holder; its photon value IS
         the FT amount (1 photon = 1 unit), so the whole reveal value is the fungible supply."""
    builder = GlyphBuilder()
    u = _largest_utxo(node, _COMMIT_VALUE + 3 * _RXD_RELAY_FEE)
    key = PrivateKey(str(node.rxd("dumpprivkey", u["address"])))
    pkh = Hex20(key.public_key().hash160())
    spk = bytes.fromhex(u["scriptPubKey"])
    in_sats = round(u["amount"] * 1e8)

    if is_nft:
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="ETH-RXD-REAL-NFT", token_type="object")
    else:
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name="ETH-RXD-REAL-FT", ticker="ERFT", decimals=0)
    commit = builder.prepare_commit(
        CommitParams(metadata=meta, owner_pkh=pkh, change_pkh=pkh, funding_satoshis=in_sats)
    )
    fin = TransactionInput(
        source_transaction=_src(u["txid"], int(u["vout"]), spk, in_sats),
        source_txid=u["txid"],
        source_output_index=int(u["vout"]),
        unlocking_script_template=_p2pkh_unlock(key),
    )
    fin.satoshis = in_sats
    fin.locking_script = Script(spk)
    change_spk = b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"
    commit_tx = Transaction(
        tx_inputs=[fin],
        tx_outputs=[
            TransactionOutput(Script(commit.commit_script), _COMMIT_VALUE),
            TransactionOutput(Script(change_spk), in_sats - _COMMIT_VALUE - _RXD_RELAY_FEE),
        ],
    )
    commit_tx.sign()
    commit_txid = str(node.rxd("sendrawtransaction", commit_tx.serialize().hex()))
    node.rxd_mine(1)

    rev = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=_COMMIT_VALUE,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=pkh,
            is_nft=is_nft,
        )
    )
    rin = TransactionInput(
        source_transaction=_src(commit_txid, 0, commit.commit_script, _COMMIT_VALUE),
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=_glyph_unlock(key, rev.scriptsig_suffix),
    )
    rin.satoshis = _COMMIT_VALUE
    rin.locking_script = Script(commit.commit_script)
    reveal_value = _COMMIT_VALUE - _RXD_RELAY_FEE
    reveal_tx = Transaction(tx_inputs=[rin], tx_outputs=[TransactionOutput(Script(rev.locking_script), reveal_value)])
    reveal_tx.sign()
    reveal_txid = str(node.rxd("sendrawtransaction", reveal_tx.serialize().hex()))
    node.rxd_mine(2)
    return _Minted(f"{reveal_txid}:0", reveal_txid, key, rev.locking_script, reveal_value, is_nft)


async def _wait_indexed(ws_url, ref, attempts=30):
    """Poll the REAL RXinDexer until it resolves the freshly-minted token (or fail)."""
    import asyncio

    for _ in range(attempts):
        c = ElectrumXClient(urls=[ws_url], allow_insecure=True)
        try:
            tok = await RxinDexerClient(c).glyph_get_token(ref)
        finally:
            close = getattr(c, "close", None)
            if close:
                try:
                    await close()
                except Exception:
                    pass
        if tok:
            return
        await asyncio.sleep(2)
    raise RuntimeError(f"RXinDexer never indexed {ref}")


def _spend_singleton_into_covenant(node, dest_spk, dest_value, *, minted: _Minted):
    """Spend the REAL minted singleton (``reveal_txid:0``) into the covenant — so the genuine genesis
    outpoint enters the covenant's input-ref set (the covenant binds genesis_txid=reveal_txid).

    Both the NFT (``d8 <ref> OP_DROP <p2pkh>``) and the FT (``p2pkh + <conservation epilogue>``)
    holder scripts start with a P2PKH that the owner key's sig+pubkey satisfies — the ref/epilogue
    opcodes self-consume during validation — so a P2PKH unlock is correct for both.

    NFT: a single input (singleton -> covenant carrier) suffices; fee comes out of the value delta.
    FT:  the conservation epilogue requires the covenant output to carry the FULL FT amount
         (``dest_value == reveal_value``), so the relay fee must come from a SEPARATE RXD input
         (proven via testmempoolaccept 2026-06-01: same-value FT spend with no fee input is rejected
         only for "min relay fee not met"; adding a fee input + change is accepted)."""
    rin = TransactionInput(
        source_transaction=_src(minted.reveal_txid, 0, minted.locking_script, minted.reveal_value),
        source_txid=minted.reveal_txid,
        source_output_index=0,
        unlocking_script_template=_p2pkh_unlock(minted.owner_key),
    )
    rin.satoshis = minted.reveal_value
    rin.locking_script = Script(minted.locking_script)
    outs = [TransactionOutput(Script(dest_spk), dest_value)]
    inputs = [rin]
    if not minted.is_nft:
        # FT: pull a separate fee input + send change back to a fresh wallet address.
        f = _largest_utxo(node, 3 * _RXD_RELAY_FEE)
        fkey = PrivateKey(str(node.rxd("dumpprivkey", f["address"])))
        fspk = bytes.fromhex(f["scriptPubKey"])
        fval = round(f["amount"] * 1e8)
        feein = TransactionInput(
            source_transaction=_src(f["txid"], int(f["vout"]), fspk, fval),
            source_txid=f["txid"],
            source_output_index=int(f["vout"]),
            unlocking_script_template=_p2pkh_unlock(fkey),
        )
        feein.satoshis = fval
        feein.locking_script = Script(fspk)
        inputs.append(feein)
        change_spk = b"\x76\xa9\x14" + bytes(Hex20(fkey.public_key().hash160())) + b"\x88\xac"
        outs.append(TransactionOutput(Script(change_spk), fval - _RXD_RELAY_FEE))
    tx = Transaction(tx_inputs=inputs, tx_outputs=outs)
    tx.sign()
    txid = str(node.rxd("sendrawtransaction", tx.serialize().hex()))
    node.rxd_mine(1)
    return txid


def _eth_policy():
    return MarginPolicy(
        margin=bt.Timelock(36, bt.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
        cross_clock_margin=CrossClockMargin(
            eth_reorg_finality_s=768, rxd_claim_burial_s=1800, rxd_confirm_slack_s=600, rounding_slack_s=300
        ),
        max_covenant_confirm_wait_s=600,
    )


@pytest.fixture(scope="module")
def env():
    if not os.environ.get("XCHAIN_ETH_GLYPH_REAL"):
        pytest.skip("XCHAIN_ETH_GLYPH_REAL not set (opt-in: requires a running RXinDexer-indexed node)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if shutil.which("anvil") is None:
        pytest.skip("anvil not available")
    node = _IndexedNode()
    # Sanity: the node is reachable and is regtest.
    if not isinstance(node.rxd("getblockchaininfo"), dict) or node.rxd("getblockchaininfo")["chain"] != "regtest":
        pytest.skip("RXD_NODE_CT is not a reachable regtest node")
    ws_url = os.environ.get("RXINDEXER_WS", "ws://127.0.0.1:50011")
    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    anvil = subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", str(_CHAIN_ID), "--slots-in-an-epoch", "1", "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                _anvil_rpc(url, "eth_chainId")
                break
            except Exception:
                time.sleep(0.1)
        else:
            pytest.fail("anvil did not become ready")
        yield node, url, ws_url
    finally:
        anvil.terminate()


class TestEthRealGlyphSwap:
    @pytest.mark.parametrize("asset_variant", ["nft", "ft"])
    async def test_happy_path_with_real_minted_glyph_and_rxindexer(self, env, asset_variant):
        """ETH↔(real NFT|FT Glyph) settles end-to-end with the REAL RxinDexerRefAdapter as the
        pre-lock authenticity oracle — not the FakeIndexer, not a fake singleton.

        The FT case additionally exercises the on-chain conservation epilogue: the genuine FT
        singleton is spent into the FT covenant with the full FT amount conserved (covenant value ==
        reveal value) + a separate RXD fee input."""
        node, url, ws_url = env
        is_nft = asset_variant == "nft"

        # 0. Mint a genuine Glyph; wait for the real RXinDexer to index it.
        minted = _mint_glyph(node, is_nft=is_nft)
        # Bury the genesis >=6 deep: the REAL adapter reads live confs and the pre-lock REF gate
        # fails closed on a shallow genesis (it can be reorged out after payment). The FakeIndexer
        # always reported deep confs, so this real-world burial requirement was never exercised.
        node.rxd_mine(6)
        await _wait_indexed(ws_url, minted.ref_str)
        ref_txid, ref_vout = minted.ref_str.split(":")
        genesis_ref = GlyphRef(txid=ref_txid, vout=int(ref_vout)).to_bytes()

        # 1. Build the covenant bound to the GENUINE genesis ref.
        #    NFT: a small fixed carrier value. FT: the covenant must carry the FULL minted FT amount
        #    (1 photon = 1 unit) for the conservation epilogue to be satisfied on the lock spend.
        p_secret = SecretBytes(os.urandom(32))
        h = hashlib.sha256(p_secret.unsafe_raw_bytes()).digest()
        carrier = 1000 if is_nft else minted.reveal_value
        t_rxd = bt.Timelock(60, bt.TimeUnit.BLOCKS)
        t_btc = bt.Timelock(100, bt.TimeUnit.BLOCKS)
        eth_timeout = _anvil_now(url) + 50_000

        taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
        taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
        maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))

        if is_nft:
            cov = build_htlc_covenant_nft(
                genesis_txid=ref_txid,
                genesis_vout=int(ref_vout),
                nft_carrier_value=carrier,
                taker_pkh=taker_pkh,
                maker_pkh=maker_pkh,
                hashlock=h,
                refund_csv=t_rxd.value,
            )
        else:
            cov = build_htlc_covenant_ft(
                genesis_txid=ref_txid,
                genesis_vout=int(ref_vout),
                amount=carrier,
                taker_pkh=taker_pkh,
                maker_pkh=maker_pkh,
                hashlock=h,
                refund_csv=t_rxd.value,
            )

        # 2. The REAL authenticity oracle: RxinDexerRefAdapter over ws:// + the node for confs.
        rxd_client = _RadiantCliClient(node)
        rxd_client.register_spk(cov.funded_spk)
        chain_io = RadiantChainIO(rxd_client)
        ex = ElectrumXClient(urls=[ws_url], allow_insecure=True)
        indexer = RxinDexerRefAdapter(RxinDexerClient(ex), chain_io)

        terms = NegotiatedTerms(
            hashlock=h,
            btc_sats=100_000,
            radiant_amount=carrier,
            t_btc=t_btc,
            t_rxd=t_rxd,
            asset_variant=asset_variant,
            genesis_ref=genesis_ref,
            taker_dest_hash=cov.expected_taker_hash,
            maker_dest_hash=cov.expected_maker_hash,
            btc_claim_pubkey_xonly=b"\x00" * 32,
            btc_refund_pubkey_xonly=b"\x00" * 32,
            counter_chain="eth",
            value_amount=_ETH_AMOUNT_WEI,
            eth_timeout_unix_s=eth_timeout,
        )

        from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
        from pyrxd.eth_wallet.rpc import EthRpc

        rpc = EthRpc(url, expected_chain_id=_CHAIN_ID)
        contract_leg = EthHtlcContractLeg(
            rpc=rpc, signing_key=PrivateKeyMaterial(bytes.fromhex(_KEY)), chain_id=_CHAIN_ID, artifact=_ARTIFACT
        )
        eth_leg = _RecordingEthLeg(
            EthLeg(
                contract_leg=contract_leg,
                network="anvil",
                claim_to=_ADDR_MAKER,
                refund_to=_ADDR_TAKER,
                eth_timeout_unix_s=eth_timeout,
                audit_cleared=True,
            )
        )
        rxd_leg = RadiantCovenantLeg(
            network="bcrt",
            taker_pkh=taker_pkh,
            maker_pkh=maker_pkh,
            chain_io=chain_io,
            fee_source=_FeeSource(node),
            min_confirmations=1,
        )
        coord = SwapCoordinator(
            record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
            counter_leg=eth_leg,
            radiant_leg=rxd_leg,
            indexer=indexer,
            seen_store=_MemSeen(),
            config=CoordinatorConfig(margin_policy=_eth_policy(), accept_nondurable_seen=True),
        )

        now_unix = _anvil_now(url)
        # 3. Taker deploys + funds the ETH HTLC on Anvil.
        rec = await coord.taker_funds_btc(terms, now_unix_s=now_unix)
        assert rec.state is SwapState.BTC_LOCKED

        # 4. Maker locks the REAL minted singleton into the covenant; taker re-validates SPK + REF
        #    (through the REAL RXinDexer) + cross-clock.
        asset_locked_at = int(node.rxd("getblockcount"))
        _spend_singleton_into_covenant(node, cov.funded_spk, carrier, minted=minted)
        rec = await coord.post_asset_lock_revalidate(cov.funded_spk, now_unix_s=_anvil_now(url))
        assert rec.state is SwapState.BOTH_LOCKED

        # 5. Maker claims the ETH (reveals p), taker scrapes + claims the asset (FINAL → SAFE).
        rec = await coord.maker_claims_btc(p_secret)
        assert rec.state is SwapState.SECRET_REVEALED
        claim_tx = eth_leg.last_claim_tx
        assert claim_tx is not None
        _anvil_mine(url, 3)

        now_rxd = int(node.rxd("getblockcount"))
        rec = await coord.taker_scrape_and_claim_asset(
            claim_tx, now_rxd_height=now_rxd, asset_locked_at_height=asset_locked_at
        )
        assert rec.state is SwapState.COMPLETED

        cov_txid = rec.radiant_covenant_outpoint.split(":")[0]
        assert node.rxd("gettxout", cov_txid, "0") in (None, ""), "NFT covenant should be spent after claim"
        await rpc.close()
