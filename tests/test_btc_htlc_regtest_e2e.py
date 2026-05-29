"""BTC-side end-to-end HTLC proof on a real Bitcoin Core regtest node.

The Bitcoin half of the T7 cross-chain HTLC swap. Proves the taproot HTLC builders
(:mod:`pyrxd.btc_wallet.taproot` — ``build_htlc``/``build_claim_tx``/
``build_refund_tx``/``scrape_secret``) are accepted by REAL Bitcoin consensus with
taproot active — the script-path P2TR spends, not just BIP341 test vectors:

* the P2TR HTLC funds (wallet ``sendtoaddress`` to the ``bcrt1p…`` address);
* ``claim`` (hashlock leaf, preimage in the witness) is ACCEPTED and spends it;
* a claim whose preimage does NOT open the funded taptree is REJECTED (witness
  program mismatch);
* the preimage is scrapeable from the on-chain claim witness (the cross-chain
  secret-reveal the Radiant taker relies on);
* a PREMATURE CSV refund is REJECTED (BIP68 non-final);
* a MATURED CSV refund (v2 + nSequence) is ACCEPTED and spends it.

Pairs with tests/test_htlc_regtest_e2e.py (the Radiant half). Together they prove
both legs on their real chains; the coordinator drives them in production.

Gating (matches the integration convention):
* ``@pytest.mark.integration`` — deselected by default ``-m 'not integration'``.
* Opt-in: set ``BTC_REGTEST=1`` to run. Skips (not fails) if docker is unavailable
  or the Bitcoin Core image can't be pulled.

The test manages its OWN isolated bitcoind regtest container, funds a throwaway
wallet, mines its own blocks, and tears down afterward. Moves no real value.

Run it:  BTC_REGTEST=1 pytest tests/test_btc_htlc_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t

pytestmark = pytest.mark.integration

_IMAGE = "ruimarinho/bitcoin-core:24"
_CONTAINER = "gravity-btc-regtest-pytest"
_FEE_SATS = 2_000
_REFUND_CSV = 3


class _BtcRegtest:
    """A self-managed isolated bitcoind regtest node (docker)."""

    def __init__(self) -> None:
        self.user = "btc_user"
        self.password = secrets.token_hex(12)
        self.mine_addr = ""

    def cli(self, *args: str, wallet: bool = False) -> object:
        base = [
            "docker",
            "exec",
            _CONTAINER,
            "bitcoin-cli",
            "-regtest",
            f"-rpcuser={self.user}",
            f"-rpcpassword={self.password}",
        ]
        if wallet:
            base.append("-rpcwallet=btcw")
        r = subprocess.run(base + list(args), capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"bitcoin-cli {args[0]} failed: {r.stderr.strip()}")
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
                _IMAGE,
                "-regtest",
                "-server",
                "-txindex=1",
                "-fallbackfee=0.0002",
                f"-rpcuser={self.user}",
                f"-rpcpassword={self.password}",
                "-rpcbind=0.0.0.0",
                "-rpcallowip=0.0.0.0/0",
            ],
            capture_output=True,
            text=True,
        )
        if up.returncode != 0:
            raise RuntimeError(f"failed to start bitcoind regtest container: {up.stderr.strip()}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                info = self.cli("getblockchaininfo")
                if isinstance(info, dict) and info.get("chain") == "regtest":
                    break
            except RuntimeError:
                time.sleep(0.5)
        else:
            raise RuntimeError("bitcoind regtest RPC did not become ready")
        assert self.cli("getblockchaininfo")["chain"] == "regtest", "node is NOT regtest — aborting"
        # Taproot must be active for the P2TR script-path spends.
        dep = self.cli("getdeploymentinfo")
        tr = dep["deployments"]["taproot"] if isinstance(dep, dict) and "deployments" in dep else {}
        assert tr.get("active") is True, "taproot is not active on this regtest node"
        self.cli("createwallet", "btcw")
        self.mine_addr = str(self.cli("getnewaddress", wallet=True))
        self.mine(101)

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", _CONTAINER], capture_output=True)

    # -- helpers the tests use ------------------------------------------------
    def fund_htlc(self, htlc) -> t.BtcHtlcLocator:
        """sendtoaddress the HTLC P2TR address; return a funded locator."""
        ftxid = self.cli("sendtoaddress", htlc.address, "0.001", wallet=True)
        assert isinstance(ftxid, str), f"fund failed: {ftxid}"
        self.mine(1)
        ftx = self.cli("getrawtransaction", ftxid, "true")
        vout = next(o["n"] for o in ftx["vout"] if o["scriptPubKey"]["hex"] == htlc.scriptpubkey.hex())
        funded_sats = round(ftx["vout"][vout]["value"] * 1e8)
        return htlc.with_funding(t.BtcOutpoint(ftxid, vout), funded_sats)

    def payout_spk(self) -> bytes:
        addr = self.cli("getnewaddress", wallet=True)
        return bytes.fromhex(self.cli("getaddressinfo", addr, wallet=True)["scriptPubKey"])


@pytest.fixture(scope="module")
def btc():
    if not os.environ.get("BTC_REGTEST"):
        pytest.skip("BTC_REGTEST not set (opt-in for the live bitcoind e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    # Ensure the image is present (pull if needed); skip if we can't get it.
    have = subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True)
    if have.returncode != 0:
        pull = subprocess.run(["docker", "pull", _IMAGE], capture_output=True, timeout=300)
        if pull.returncode != 0:
            pytest.skip(f"could not obtain {_IMAGE}")
    n = _BtcRegtest()
    n.start()
    try:
        yield n
    finally:
        n.stop()


def _htlc_keys():
    maker = coincurve.PrivateKey(os.urandom(32))  # claim key
    taker = coincurve.PrivateKey(os.urandom(32))  # refund key
    return (
        maker,
        taker,
        coincurve.PublicKeyXOnly.from_secret(maker.secret).format(),
        coincurve.PublicKeyXOnly.from_secret(taker.secret).format(),
    )


class TestBtcHtlcOnConsensus:
    def test_claim_accepted_wrong_preimage_rejected_and_scrapeable(self, btc):
        maker, _taker, claim_xo, refund_xo = _htlc_keys()
        p = os.urandom(32)
        h = hashlib.sha256(p).digest()
        timeout = t.Timelock(_REFUND_CSV, t.TimeUnit.BLOCKS)
        htlc = t.build_htlc(
            hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo, timeout=timeout, network="bcrt"
        )
        locator = btc.fund_htlc(htlc)
        payout = btc.payout_spk()

        # Correct preimage claim: accepted.
        claim = t.build_claim_tx(
            locator=locator,
            preimage=p,
            claim_privkey=maker.secret,
            to_scriptpubkey=payout,
            fee_sats=_FEE_SATS,
            aux_rand=os.urandom(32),
        )
        res = btc.accepts(claim.hex())
        assert res["allowed"] is True, res

        # A claim whose preimage does NOT open the funded taptree -> witness program
        # mismatch. (Build an HTLC for a different H pointing at the real UTXO.)
        wrong_p = os.urandom(32)
        wrong_htlc = t.build_htlc(
            hashlock=hashlib.sha256(wrong_p).digest(),
            claim_pubkey_xonly=claim_xo,
            refund_pubkey_xonly=refund_xo,
            timeout=timeout,
            network="bcrt",
        )
        wrong_loc = wrong_htlc.with_funding(locator.funding_outpoint, locator.amount_sats)
        wrong_claim = t.build_claim_tx(
            locator=wrong_loc,
            preimage=wrong_p,
            claim_privkey=maker.secret,
            to_scriptpubkey=payout,
            fee_sats=_FEE_SATS,
            aux_rand=os.urandom(32),
        )
        neg = btc.accepts(wrong_claim.hex())
        assert neg["allowed"] is False
        assert "mismatch" in neg.get("reject-reason", "").lower() or "script-verify" in neg.get("reject-reason", ""), (
            neg
        )

        # Broadcast the good claim; confirm spend + preimage scrapeable from the witness.
        ctxid = btc.cli("sendrawtransaction", claim.hex())
        assert isinstance(ctxid, str)
        btc.mine(1)
        spent = btc.cli("gettxout", locator.funding_outpoint.txid, str(locator.funding_outpoint.vout))
        assert spent in (None, ""), "HTLC UTXO should be spent after claim"
        assert t.scrape_secret(claim, h) == p, "preimage must be scrapeable from the on-chain claim"

    def test_premature_refund_rejected_matured_accepted(self, btc):
        _maker, taker, claim_xo, refund_xo = _htlc_keys()
        p = os.urandom(32)
        h = hashlib.sha256(p).digest()
        timeout = t.Timelock(_REFUND_CSV, t.TimeUnit.BLOCKS)
        htlc = t.build_htlc(
            hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo, timeout=timeout, network="bcrt"
        )
        locator = btc.fund_htlc(htlc)
        payout = btc.payout_spk()

        refund = t.build_refund_tx(
            locator=locator,
            refund_privkey=taker.secret,
            timeout=timeout,
            to_scriptpubkey=payout,
            fee_sats=_FEE_SATS,
            aux_rand=os.urandom(32),
        )
        raw = refund.hex()

        # Premature -> BIP68 non-final.
        res = btc.accepts(raw)
        assert res["allowed"] is False
        assert "BIP68" in res.get("reject-reason", "") or "non-final" in res.get("reject-reason", ""), res

        # Mature the relative timelock; the SAME tx is now accepted + spends it.
        btc.mine(_REFUND_CSV)
        res = btc.accepts(raw)
        assert res["allowed"] is True, res
        rtxid = btc.cli("sendrawtransaction", raw)
        assert isinstance(rtxid, str)
        btc.mine(1)
        spent = btc.cli("gettxout", locator.funding_outpoint.txid, str(locator.funding_outpoint.vout))
        assert spent in (None, ""), "HTLC UTXO should be spent after refund"
