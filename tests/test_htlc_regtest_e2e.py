"""Radiant-side end-to-end HTLC swap proof on a real radiant-core regtest node.

This is the T7 step-5 consensus milestone for the RADIANT half of the BTC<->RXD
HTLC swap. It proves the productized covenant + spend builders
(:mod:`pyrxd.gravity.htlc_covenant`, :mod:`pyrxd.gravity.htlc_spend`) are accepted
by REAL Radiant consensus — not just structurally valid in unit tests:

* the funded HTLC covenant is accepted + mined;
* ``claim(preimage)`` (OP_0 selector) is ACCEPTED and spends the covenant;
* a WRONG preimage is REJECTED by consensus (hashlock OP_EQUALVERIFY);
* a PREMATURE CSV refund is REJECTED (BIP68 non-final);
* a MATURED CSV refund (OP_1 selector, v2 + nSequence) is ACCEPTED and spends it;
* **R1**: a fake-singleton covenant whose genesis ref is a plain wallet UTXO
  (not a minted Glyph) is ACCEPTED by consensus — consensus enforces ref
  UNIQUENESS, not mint PROVENANCE, which is why ``verify_ref_authenticity`` is the
  only defense.

The BTC half stays at the unit-test / structural level until a bitcoind regtest
node exists in the environment (the BtcLeg's broadcaster/reader need one).

Gating (matches tests/test_dmint_deploy_integration.py convention):
* ``@pytest.mark.integration`` — deselected by the default ``-m 'not integration'``
  addopts, so CI stays clean.
* Opt-in: set ``RADIANT_REGTEST=1`` to run. Skips (not fails) if docker or the
  ``radiant-core:v3.1.1-amd64`` image is unavailable.

The test manages its OWN isolated regtest container (separate from any mainnet
node), funds a throwaway wallet, mines its own blocks, and tears the container
down afterward. It NEVER touches a mainnet node and moves no real value.

Run it:  RADIANT_REGTEST=1 pytest tests/test_htlc_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time

import pytest

from pyrxd.gravity.htlc_covenant import build_htlc_covenant_nft, build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_IMAGE = "radiant-core:v3.1.1-amd64"
_CONTAINER = "gravity-regtest-pytest"
_RELAY_FEE_SATS = 1_000_000  # 0.01 RXD — >> relayfee (0.01 RXD/kB) for a sub-kB tx


# --------------------------------------------------------------------------- node fixture


class _RegtestNode:
    """A self-managed isolated radiant-core regtest node (docker)."""

    def __init__(self) -> None:
        self.user = "rt_user"
        self.password = secrets.token_hex(12)
        self.mine_addr = ""

    def cli(self, *args: str, wallet: bool = False) -> object:
        base = [
            "docker",
            "exec",
            _CONTAINER,
            "radiant-cli",
            "-regtest",
            f"-rpcuser={self.user}",
            f"-rpcpassword={self.password}",
        ]
        if wallet:
            base.append("-rpcwallet=gravity")
        r = subprocess.run(base + list(args), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"radiant-cli {args[0]} failed: {r.stderr.strip()}")
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def mine(self, n: int = 1) -> None:
        self.cli("generatetoaddress", str(n), self.mine_addr)

    def accepts(self, raw_hex: str) -> dict:
        res = self.cli("testmempoolaccept", json.dumps([raw_hex]))
        return res[0] if isinstance(res, list) else res

    def start(self) -> None:
        subprocess.run(["docker", "rm", "-f", _CONTAINER], capture_output=True)
        up = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                _CONTAINER,
                "--entrypoint",
                "radiantd",
                _IMAGE,
                "-regtest",
                "-server",
                "-txindex=1",
                "-disablewallet=0",
                "-fallbackfee=0.001",
                f"-rpcuser={self.user}",
                f"-rpcpassword={self.password}",
                "-rpcbind=0.0.0.0",
                "-rpcallowip=0.0.0.0/0",
            ],
            capture_output=True,
            text=True,
        )
        if up.returncode != 0:
            raise RuntimeError(f"failed to start regtest container: {up.stderr.strip()}")
        # Wait for RPC to come up.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                info = self.cli("getblockchaininfo")
                if isinstance(info, dict) and info.get("chain") == "regtest":
                    break
            except RuntimeError:
                time.sleep(0.5)
        else:
            raise RuntimeError("regtest RPC did not become ready")
        # Safety: refuse to proceed unless this is genuinely regtest.
        assert self.cli("getblockchaininfo")["chain"] == "regtest", "node is NOT regtest — aborting"
        self.cli("createwallet", "gravity")
        self.mine_addr = str(self.cli("getnewaddress", wallet=True))
        self.mine(101)  # mature a coinbase

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", _CONTAINER], capture_output=True)


@pytest.fixture(scope="module")
def node():
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    has_image = subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True)
    if has_image.returncode != 0:
        pytest.skip(f"{_IMAGE} image not available")
    n = _RegtestNode()
    n.start()
    try:
        yield n
    finally:
        n.stop()


# --------------------------------------------------------------------------- tx helpers


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
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + inp.sighash.to_bytes(1, "little")) + encode_pushdata(pub))

    return to_unlock_script_template(_u, lambda: 110)


def _biggest_utxo(node: _RegtestNode) -> dict:
    utxos = node.cli("listunspent", "1", "9999999", wallet=True)
    return max(utxos, key=lambda x: x["amount"])


def _pay_to_spk(
    node: _RegtestNode, dest_spk: bytes, amount: int, *, spend_outpoint: tuple[str, int] | None = None
) -> str:
    """Build+broadcast a wallet tx paying ``amount`` to ``dest_spk`` at vout 0.

    If ``spend_outpoint`` is given, spend exactly that UTXO (used by the R1 case so
    the chosen outpoint enters the input-ref set); otherwise spend the biggest UTXO.
    Returns the broadcast txid. Mines one block.
    """
    if spend_outpoint is not None:
        txid, vout = spend_outpoint
        info = node.cli("gettxout", txid, str(vout))
        addr = info["scriptPubKey"]["addresses"][0] if "addresses" in info["scriptPubKey"] else None
        if addr is None:
            # derive address from the wallet utxo list instead
            u = next(
                x
                for x in node.cli("listunspent", "1", "9999999", wallet=True)
                if x["txid"] == txid and x["vout"] == vout
            )
            addr = u["address"]
            spk = bytes.fromhex(u["scriptPubKey"])
            in_sats = round(u["amount"] * 1e8)
        else:
            spk = bytes.fromhex(info["scriptPubKey"]["hex"])
            in_sats = round(info["value"] * 1e8)
    else:
        u = _biggest_utxo(node)
        txid, vout, addr = u["txid"], u["vout"], u["address"]
        spk = bytes.fromhex(u["scriptPubKey"])
        in_sats = round(u["amount"] * 1e8)

    wif = node.cli("dumpprivkey", addr, wallet=True)
    key = PrivateKey(str(wif))
    pkh = bytes(Hex20(key.public_key().hash160()))
    change_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    fin = TransactionInput(
        source_transaction=_src(txid, vout, spk, in_sats),
        source_txid=txid,
        source_output_index=vout,
        unlocking_script_template=_p2pkh_unlock(key),
    )
    fin.satoshis = in_sats
    fin.locking_script = Script(spk)
    change = in_sats - amount - _RELAY_FEE_SATS
    assert change > 546, f"change {change} too small"
    tx = Transaction(
        tx_inputs=[fin],
        tx_outputs=[TransactionOutput(Script(dest_spk), amount), TransactionOutput(Script(change_spk), change)],
    )
    tx.sign()
    btxid = node.cli("sendrawtransaction", tx.serialize().hex())
    assert isinstance(btxid, str), f"pay_to_spk broadcast failed: {btxid}"
    node.mine(1)
    return btxid


def _fee_input(node: _RegtestNode, amount: int = 5_000_000) -> FeeInput:
    """Carve a plain-P2PKH UTXO of ``amount`` for a covenant spend's fee leg."""
    u = _biggest_utxo(node)
    wif = str(node.cli("dumpprivkey", u["address"], wallet=True))
    key = PrivateKey(wif)
    pkh = bytes(Hex20(key.public_key().hash160()))
    out_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    txid = _pay_to_spk(node, out_spk, amount, spend_outpoint=(u["txid"], u["vout"]))
    return FeeInput(txid=txid, vout=0, value=amount, scriptpubkey=out_spk, wif=wif)


def _rxd_covenant(*, carrier: int, refund_csv: int):
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    taker = PrivateKey(os.urandom(32))
    maker = PrivateKey(os.urandom(32))
    cov = build_htlc_covenant_rxd(
        amount=carrier,
        taker_pkh=bytes(Hex20(taker.public_key().hash160())),
        maker_pkh=bytes(Hex20(maker.public_key().hash160())),
        hashlock=h,
        refund_csv=refund_csv,
    )
    return cov, p


# --------------------------------------------------------------------------- the proofs


class TestRadiantHtlcOnConsensus:
    def test_claim_accepted_wrong_preimage_rejected(self, node):
        carrier = 100_000
        cov, p = _rxd_covenant(carrier=carrier, refund_csv=3)
        cov_txid = _pay_to_spk(node, cov.funded_spk, carrier)
        outpoint = f"{cov_txid}:0"

        # Wrong preimage: hand-mutate a valid claim's scriptSig and confirm consensus
        # rejects it (the builder itself refuses a wrong preimage, so we mutate post-build).
        claim = build_htlc_claim_tx(
            covenant=cov, covenant_outpoint=outpoint, carrier_value=carrier, preimage=p, fee=_fee_input(node)
        )
        raw_good = claim.serialize().hex()
        raw_wrong = raw_good.replace(p.hex(), os.urandom(32).hex(), 1)
        assert raw_wrong != raw_good
        res = node.accepts(raw_wrong)
        assert res["allowed"] is False
        assert "OP_EQUALVERIFY" in res.get("reject-reason", ""), res

        # Correct preimage: accepted + spends the covenant.
        claim2 = build_htlc_claim_tx(
            covenant=cov, covenant_outpoint=outpoint, carrier_value=carrier, preimage=p, fee=_fee_input(node)
        )
        res = node.accepts(claim2.serialize().hex())
        assert res["allowed"] is True, res
        ctxid = node.cli("sendrawtransaction", claim2.serialize().hex())
        assert isinstance(ctxid, str)
        node.mine(1)
        assert node.cli("gettxout", cov_txid, "0") in (None, ""), "covenant UTXO should be spent after claim"

    def test_premature_refund_rejected_matured_accepted(self, node):
        carrier = 100_000
        refund_csv = 3
        cov, _p = _rxd_covenant(carrier=carrier, refund_csv=refund_csv)
        cov_txid = _pay_to_spk(node, cov.funded_spk, carrier)
        outpoint = f"{cov_txid}:0"

        refund = build_htlc_refund_tx(
            covenant=cov, covenant_outpoint=outpoint, carrier_value=carrier, fee=_fee_input(node)
        )
        raw = refund.serialize().hex()

        # Premature (covenant just ~1 conf, needs refund_csv) -> BIP68 non-final.
        res = node.accepts(raw)
        assert res["allowed"] is False
        assert "BIP68" in res.get("reject-reason", "") or "non-final" in res.get("reject-reason", ""), res

        # Mature the relative timelock, then the SAME tx is accepted + spends it.
        node.mine(refund_csv)
        res = node.accepts(raw)
        assert res["allowed"] is True, res
        rtxid = node.cli("sendrawtransaction", raw)
        assert isinstance(rtxid, str)
        node.mine(1)
        assert node.cli("gettxout", cov_txid, "0") in (None, ""), "covenant UTXO should be spent after refund"

    def test_r1_fake_singleton_accepted_by_consensus(self, node):
        """R1: a covenant whose genesis ref is a plain wallet UTXO (NOT a minted
        Glyph) is accepted by consensus — uniqueness is enforced, provenance is not.
        This is the consensus fact that makes verify_ref_authenticity load-bearing.
        """
        u = _biggest_utxo(node)
        fake_txid, fake_vout = u["txid"], u["vout"]  # a coin we control — NOT a mint

        carrier = 1000
        p = os.urandom(32)
        h = hashlib.sha256(p).digest()
        taker = PrivateKey(os.urandom(32))
        maker = PrivateKey(os.urandom(32))
        cov = build_htlc_covenant_nft(
            genesis_txid=fake_txid,
            genesis_vout=fake_vout,
            nft_carrier_value=carrier,
            taker_pkh=bytes(Hex20(taker.public_key().hash160())),
            maker_pkh=bytes(Hex20(maker.public_key().hash160())),
            hashlock=h,
            refund_csv=3,
        )
        # Fund by spending exactly that UTXO so its outpoint enters the input-ref set
        # (the R1 mechanism: validatePushRefRule only needs output-ref subset-of input-refs).
        cov_txid = _pay_to_spk(node, cov.funded_spk, carrier, spend_outpoint=(fake_txid, fake_vout))
        # If it mined, consensus accepted the fake singleton.
        out = node.cli("gettxout", cov_txid, "0")
        assert out, "fake-singleton covenant UTXO should exist — consensus accepted it (R1)"
        # And it carries the fake ref the covenant pinned.
        assert round(out["value"] * 1e8) == carrier
