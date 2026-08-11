"""Live-node proof of the fee floors, AT THE MAINNET RATE — not a tenth of it.

Why this file exists and the other regtest suites did not suffice
----------------------------------------------------------------
A default ``radiantd -regtest`` advertises ``effective_minrelaytxfee`` **0.01
RXD/kB** — a tenth of what mainnet enforces. pyrxd's builders default to
``10_000`` photons/byte, which is *exactly* the mainnet floor (0.10 RXD/kB). So
every existing regtest suite that broadcasts a builder's output is over-paying its
node by 10x, and a transaction one or two bytes short of its own rate is accepted
anyway. That is not a gap in those suites' assertions; it is a gap in what a node
at a tenth of the rate is *able* to say.

``tests/test_container_regtest_e2e.py`` is the concrete case: it builds NFT
transfers at ``_MIN_FEE_RATE = 10_000`` and puts them to a node whose floor is
1_000, so the ``build_nft_transfer_tx`` undersizing (24.9% of builds, measured over
3000 fresh keys) could never surface there.

This node therefore runs with ``-minrelaytxfee=0.10``, and every case asserts
``getmempoolinfo`` reports that back before proving anything. What it rejects here
is what mainnet rejects.

The defect, proven before the fix
---------------------------------
Run against the unfixed ``build_nft_transfer_tx``, on this node, 12 transfers built
at the default rate::

    node getmempoolinfo: minrelaytxfee=0.1 effective=0.1
      #0: size=229B fee=2300000 required=2290000 -> ACCEPT
      #1: size=230B fee=2300000 required=2300000 -> ACCEPT
      #2: size=230B fee=2290000 required=2300000 -> REJECT[66: min relay fee not met]
      ...
      #10: size=230B fee=2290000 required=2300000 -> REJECT[66: min relay fee not met]
    accepted=10 rejected=2

Two of twelve real NFT transfers, refused by a real node, for the fee. The suite
below is the regression: the same builds, all accepted, plus a hand-built boundary
pair that proves the node is genuinely refusing at that line.

What each case proves
---------------------
1. The node is at the mainnet floor (``getmempoolinfo``), and one photon under it
   is refused while exactly at it is accepted. Without this pair, every "accepted"
   below would be equally true of a node that rejects nothing.
2. Every ``build_nft_transfer_tx`` output relays, over many fresh keys, on a real
   singleton NFT the node itself minted and will re-check the ref of.
3. The transfer confirms and the ref survives — the fee fix did not buy relay by
   breaking the token.
4. A transfer forced past the guard (headroom removed) is rejected by the node,
   with its reason quoted. That is the differential: same builder, one constant
   changed, opposite verdict from consensus.
5. The v3 covenant cancel and refund builders' floors are the NODE's floor: at the
   floor accepted, one photon under refused.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Manages its own
throwaway container under a DISTINCT name (the shared one is force-removed by name
at start, so a second suite sharing it would destroy the first's node). REGTEST
ONLY — no mainnet node is contacted and no real value moves. Every key comes from
``PrivateKey()`` / ``os.urandom(32)``.

Run::

    RADIANT_REGTEST=1 pytest tests/test_fee_floor_boundary_regtest_e2e.py -m integration -s
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

# Reuse the isolated-regtest harness wholesale (the house pattern). Bare module name,
# NOT ``tests.X``: pytest's prepend import mode puts ``tests/`` on sys.path and there
# is no ``tests/__init__.py``.
from test_htlc_regtest_e2e import _IMAGE, _RegtestNode, _src

from pyrxd.fee_sizing import relay_floor_photons_per_byte
from pyrxd.glyph.builder import MIN_FEE_RATE, GlyphBuilder, TransferParams
from pyrxd.glyph.script import build_nft_locking_script, extract_ref_from_nft_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DeadlineFeePolicy, photons_per_kb_from_rxd_per_kb
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError
from pyrxd.swap import FundingInput
from pyrxd.swap.rswp import build_covenant_cancel_tx, build_covenant_refund_tx, prepare_covenant_offer
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

#: DISTINCT from the shared harness's container. ``_RegtestNode.start`` does
#: ``docker rm -f`` on its own name, so a shared name means two suites deleting each
#: other's node mid-run.
_CONTAINER = "pyrxd-mainnet-floor-regtest-pytest"

#: The node runs at MAINNET's relay floor, not regtest's default tenth of it.
_MAINNET_FLOOR_RXD_PER_KB = "0.10"

_PLUMBING_FEE = 30_000_000  # 0.3 RXD — generous, for the funding txs this suite builds
_CARRIER = 100_000_000  # 1 RXD parked on each NFT so a real fee comes out of it
_RESERVE = 500_000_000  # 5 RXD into a covenant reservation
_EXPIRY = 200  # covenant expiry height; the refund case mines past this first

#: Rounds per NFT case. Roughly a quarter of DISTINCT transfers underpaid before the
#: fix, so 30 puts the chance of the case-4 differential seeing none at 0.75**30 ~
#: 1.8e-4 — 12 rounds would have been a 3% spurious pass. Each round mints a real
#: singleton (two transactions, two blocks) and the whole suite still runs in ~1 min.
_ROUNDS = 30

#: Forces an under-floor build into existence so the NODE can be asked about it.
_PERMISSIVE = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)


@pytest.fixture(scope="module")
def node():
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_IMAGE} image not available")
    n = _RegtestNode(
        container=_CONTAINER,
        extra_args=(f"-minrelaytxfee={_MAINNET_FLOOR_RXD_PER_KB}",),
    )
    n.start()
    try:
        yield n
    finally:
        n.stop()


# --------------------------------------------------------------------------- helpers


def _node_rate(rt: _RegtestNode) -> int:
    """Photons per BYTE this node enforces, read from the node itself.

    ``effective_minrelaytxfee``, not ``minrelaytxfee``: the node reports both and
    only the first is what ``AcceptToMemoryPool`` checks against
    ``GetTotalSize()``. Reading the wrong one is exactly the trap that made
    ``DeadlineFeePolicy``'s protocol bound 10x too low.
    """
    return photons_per_kb_from_rxd_per_kb(float(rt.cli("getmempoolinfo")["effective_minrelaytxfee"])) // 1000


def _reason(res: dict) -> str:
    return str(res.get("reject-reason", "") or res.get("reject_reason", ""))


def _biggest(rt: _RegtestNode) -> dict:
    utxos = rt.cli("listunspent", "1", "9999999", wallet=True)
    return max(utxos, key=lambda u: u["amount"])


def _pay_to_spk(rt: _RegtestNode, dest_spk: bytes, amount: int, *, spend: tuple[str, int] | None = None) -> str:
    """Pay *amount* to *dest_spk* at vout 0 from a wallet UTXO. Mines. Returns the txid.

    A local copy rather than the shared harness's, because that one sizes its fee
    against a 0.01 RXD/kB node and this node relays at ten times that.
    """
    unspent = rt.cli("listunspent", "1", "9999999", wallet=True)
    u = _biggest(rt) if spend is None else next(x for x in unspent if (x["txid"], x["vout"]) == spend)
    key = PrivateKey(str(rt.cli("dumpprivkey", u["address"], wallet=True)))
    spk = bytes.fromhex(u["scriptPubKey"])
    value = round(u["amount"] * 1e8)
    inp = TransactionInput(
        source_transaction=_src(u["txid"], u["vout"], spk, value),
        source_txid=u["txid"],
        source_output_index=u["vout"],
        unlocking_script_template=P2PKH().unlock(key),
    )
    inp.satoshis, inp.locking_script = value, Script(spk)
    change = value - amount - _PLUMBING_FEE
    assert change > 546, f"funding UTXO too small: {value} - {amount} - fee = {change}"
    tx = Transaction(
        tx_inputs=[inp],
        tx_outputs=[TransactionOutput(Script(dest_spk), amount), TransactionOutput(Script(spk), change)],
    )
    tx.sign()
    txid = str(rt.cli("sendrawtransaction", tx.serialize().hex()))
    rt.mine(1)
    return txid


def _mint_nft(rt: _RegtestNode, owner: PrivateKey) -> tuple[str, bytes, GlyphRef]:
    """Create a genuine singleton NFT on chain and return ``(txid, spk, ref)``.

    A Radiant ref IS the normalized outpoint of an input the creating transaction
    spends, so: fund a throwaway P2PKH at ``(T, 0)``, then spend exactly ``(T, 0)``
    in a transaction whose output 0 is ``build_nft_locking_script(pkh, ref(T, 0))``.
    The node validates ``OP_PUSHINPUTREFSINGLETON`` against its own ref set, so what
    this suite transfers is a real singleton, not a look-alike script.
    """
    seed_key = PrivateKey()
    seed_spk = bytes(P2PKH().lock(seed_key.public_key().address()).serialize())
    seed_txid = _pay_to_spk(rt, seed_spk, _CARRIER + _PLUMBING_FEE)
    ref = GlyphRef(txid=seed_txid, vout=0)
    nft_spk = build_nft_locking_script(owner.public_key().hash160(), ref)
    inp = TransactionInput(
        source_transaction=_src(seed_txid, 0, seed_spk, _CARRIER + _PLUMBING_FEE),
        source_txid=seed_txid,
        source_output_index=0,
        unlocking_script_template=P2PKH().unlock(seed_key),
    )
    inp.satoshis, inp.locking_script = _CARRIER + _PLUMBING_FEE, Script(seed_spk)
    tx = Transaction(tx_inputs=[inp], tx_outputs=[TransactionOutput(Script(nft_spk), _CARRIER)])
    tx.sign()
    res = rt.accepts(tx.serialize().hex())
    assert res.get("allowed") is True, f"the NFT mint itself was rejected — bad fixture, not a fee result: {res}"
    txid = str(rt.cli("sendrawtransaction", tx.serialize().hex()))
    rt.mine(1)
    return txid, nft_spk, ref


def _transfer(rt: _RegtestNode, *, fee_rate: int = MIN_FEE_RATE):
    """Mint a fresh NFT and build a transfer of it. Returns ``(result, owner, ref)``."""
    owner = PrivateKey()
    txid, nft_spk, ref = _mint_nft(rt, owner)
    result = GlyphBuilder().build_nft_transfer_tx(
        TransferParams(
            nft_utxo_txid=txid,
            nft_utxo_vout=0,
            nft_utxo_value=_CARRIER,
            nft_script=nft_spk,
            new_owner_pkh=PrivateKey().public_key().hash160(),
            private_key=owner,
            fee_rate=fee_rate,
        )
    )
    return result, ref


# --------------------------------------------------------------------------- 1. the node


def test_the_node_runs_at_the_mainnet_floor_and_enforces_it(node):
    """Case 1. The premise, and the negative control for everything after it.

    Reads the floor off the node instead of assuming it, then hand-builds the same
    transaction twice — once paying exactly ``size x floor``, once one photon less —
    and requires the node to take the first and refuse the second. One photon,
    because that is the real margin: the check is
    ``nModifiedFees < GetEffectiveMinRelayFee(height).GetFee(nSize)``.
    """
    info = node.cli("getmempoolinfo")
    print(f"\nnode getmempoolinfo: minrelaytxfee={info['minrelaytxfee']} effective={info['effective_minrelaytxfee']}")
    rate = _node_rate(node)
    assert rate == relay_floor_photons_per_byte() == MIN_FEE_RATE == 10_000, (
        f"this suite is only meaningful at the MAINNET floor; the node reports {rate} photons/byte"
    )

    def hand_built(fee_for_size) -> Transaction:
        """A transaction paying EXACTLY what its own signed size asks for.

        A fixed point has to be searched for, and it does not always exist for a
        given key: the fee is part of the signed output value, so changing it
        re-signs the input and can move the DER length (69-71 bytes), which changes
        the size, which changes the fee. For some keys the iteration oscillates
        between two sizes forever. So: iterate a few times per key, and if it does
        not settle, draw a fresh key and try again.
        """
        for _ in range(12):
            key = PrivateKey()
            spk = bytes(P2PKH().lock(key.public_key().address()).serialize())
            txid = _pay_to_spk(node, spk, 200_000_000)
            size = 226
            for _ in range(6):
                inp = TransactionInput(
                    source_transaction=_src(txid, 0, spk, 200_000_000),
                    source_txid=txid,
                    source_output_index=0,
                    unlocking_script_template=P2PKH().unlock(key),
                )
                inp.satoshis, inp.locking_script = 200_000_000, Script(spk)
                tx = Transaction(
                    tx_inputs=[inp],
                    tx_outputs=[TransactionOutput(Script(spk), 200_000_000 - fee_for_size(size))],
                )
                tx.sign()
                if len(tx.serialize()) == size:
                    return tx
                size = len(tx.serialize())
        raise AssertionError("no key produced a transaction whose fee matches its own signed size")

    at_floor = hand_built(lambda s: s * rate)
    ok = node.accepts(at_floor.serialize().hex())
    assert ok.get("allowed") is True, f"node refused a fee EXACTLY at its own floor — control miscalibrated: {ok}"
    print(f"at-floor:          size={len(at_floor.serialize())}B fee={at_floor.get_fee()} -> accepted")

    short = hand_built(lambda s: s * rate - 1)
    size, fee = len(short.serialize()), short.get_fee()
    assert fee == size * rate - 1, "the control did not land exactly one photon short"
    res = node.accepts(short.serialize().hex())
    assert res.get("allowed") is False, f"node ACCEPTED a fee one photon under its own floor: {res}"
    assert "min relay fee not met" in _reason(res), f"rejected, but not for the fee: {res}"
    print(f"one photon short:  size={size}B fee={fee} (floor {size * rate}) -> {_reason(res)}")


# --------------------------------------------------------------------------- 2-4. NFT transfer


def test_every_nft_transfer_relays_at_the_mainnet_floor(node):
    """Case 2. REGRESSION, and the whole point of running this node at 0.10.

    Before the fix, on this exact node, 2 of 12 of these were refused with
    ``66: min relay fee not met`` (transcript in the module docstring). Each round
    mints a fresh singleton under a fresh key, so each transfer signs a different
    message — a fixed-key fixture signs one message forever and can never see this.
    """
    rate = _node_rate(node)
    assert rate == MIN_FEE_RATE, "not at the mainnet floor; this proves nothing"
    for i in range(_ROUNDS):
        result, _ref = _transfer(node)
        raw = result.tx.serialize()
        res = node.accepts(raw.hex())
        assert res.get("allowed") is True, (
            f"round {i}: node REJECTED an NFT transfer built at its own floor "
            f"(size {len(raw)}B, fee {result.fee}, required {len(raw) * rate}): {res}"
        )
        assert result.fee >= len(raw) * rate


def test_a_transferred_nft_confirms_and_keeps_its_ref(node):
    """Case 3. Relaying is not enough — the token has to survive, read off the chain."""
    result, ref = _transfer(node)
    txid = str(node.cli("sendrawtransaction", result.tx.serialize().hex()))
    node.mine(1)
    confirmed = node.cli("getrawtransaction", txid, "true")
    assert confirmed["confirmations"] >= 1
    spk = bytes.fromhex(confirmed["vout"][0]["scriptPubKey"]["hex"])
    assert extract_ref_from_nft_script(spk) == ref, "the singleton's ref did not survive the transfer"
    assert spk == result.new_nft_script

    # The fee the CHAIN sees must be the fee the builder reported.
    total_out = sum(round(o["value"] * 1e8) for o in confirmed["vout"])
    assert _CARRIER - total_out == result.fee


def test_without_the_headroom_the_node_rejects_the_transfer(node, monkeypatch):
    """Case 4. The differential: same builder, headroom removed, consensus disagrees.

    Restores the pre-fix sizing and asks the node about whatever the builder still
    returns. Some builds are caught by the builder's own fail-closed guard (which is
    the correct outcome and is asserted offline); the ones that slip past it — there
    are none now, but this is what would surface a regression — must at minimum not
    be accepted while underpaying. At least one round has to underpay, or this case
    is not exercising anything.
    """
    monkeypatch.setattr("pyrxd.glyph.builder.trial_size_with_slack", lambda size, n: size)
    monkeypatch.setattr(
        "pyrxd.glyph.builder.assert_pays_for_its_size",
        lambda **kw: kw["fee_paid"],  # let the underpaying build THROUGH, so the node can judge it
    )
    rate = _node_rate(node)
    rejected = 0
    reasons = set()
    for _ in range(_ROUNDS):
        result, _ref = _transfer(node)
        raw = result.tx.serialize()
        underpaying = result.fee < len(raw) * rate
        res = node.accepts(raw.hex())
        if underpaying:
            assert res.get("allowed") is False, (
                f"the node ACCEPTED an underpaying transfer ({result.fee} for {len(raw)}B at {rate}/B) — "
                "either it is not at the mainnet floor or the premise of this suite is wrong"
            )
            reasons.add(_reason(res))
            rejected += 1
    assert rejected > 0, (
        f"{_ROUNDS} transfers with the headroom removed and not one underpaid — this differential "
        "cannot detect the defect it exists to detect"
    )
    assert reasons == {"66: min relay fee not met"}, f"rejected, but not for the fee: {reasons}"
    print(f"\nheadroom removed: {rejected}/{_ROUNDS} transfers refused by the node -> {reasons}")


# --------------------------------------------------------------------------- 5. v3 covenant


def _covenant(node: _RegtestNode, maker: PrivateKey) -> Transaction:
    """A covenant reservation CONFIRMED on chain, so its spends are real spends."""
    pkh = maker.public_key().hash160()
    spk = bytes(P2PKH().lock(maker.public_key().address()).serialize())
    txid = _pay_to_spk(node, spk, _RESERVE + 50_000_000)
    reserve = prepare_covenant_offer(
        funding=[FundingInput(_src(txid, 0, spk, _RESERVE + 50_000_000), 0, maker)],
        photons=_RESERVE,
        owner_pkh=pkh,
        expiry_height=_EXPIRY,
        change_pkh=pkh,
        fee=10_000_000,
    )
    res = node.accepts(reserve.serialize().hex())
    assert res.get("allowed") is True, f"the reservation itself was rejected — bad fixture: {res}"
    node.cli("sendrawtransaction", reserve.serialize().hex())
    node.mine(1)
    return reserve


def _covenant_boundary(node: _RegtestNode, builder, label: str) -> None:
    """At the node's floor: accepted. One photon under: refused, reason quoted.

    Searched, not solved — the fee is part of the signed output value, so changing
    it re-signs the input and can move the DER length and with it the size the floor
    is derived from. The pair is built from the SAME covenant so "one under" is a
    statement about the same transaction, not a differently sized sibling.

    Two nested loops, both necessary. The inner one iterates the fee toward a fixed
    point (``fee == floor(size(fee))``); the outer draws a fresh covenant when that
    iteration oscillates between two sizes instead of settling, which it does for a
    fair fraction of keys. A single-shot probe found the boundary about three runs
    in four — good enough to look correct and bad enough to fail in CI.
    """
    rate = _node_rate(node)
    policy = DeadlineFeePolicy(relay_fee_per_kb=rate * 1000)
    for _ in range(12):
        maker = PrivateKey()
        reserved = _covenant(node, maker)
        pkh = maker.public_key().hash160()

        floor = policy.min_relay_fee(len(builder(reserved, maker, pkh, 20_000_000, _PERMISSIVE).serialize()))
        at_floor = None
        for _ in range(6):
            try:
                candidate = builder(reserved, maker, pkh, floor, policy)
            except InsufficientFundsError:
                break
            settled = policy.min_relay_fee(len(candidate.serialize()))
            if settled == floor:
                at_floor = candidate
                break
            floor = settled
        if at_floor is None:
            continue
        under = builder(reserved, maker, pkh, floor - 1, _PERMISSIVE)
        if policy.min_relay_fee(len(under.serialize())) != floor:
            continue

        # The builder itself refuses the under-floor fee...
        with pytest.raises(InsufficientFundsError, match="below the required"):
            builder(reserved, maker, pkh, floor - 1, policy)
        # ...and so does the node, for the same reason.
        res = node.accepts(under.serialize().hex())
        assert res.get("allowed") is False, f"{label}: node ACCEPTED one photon under its floor: {res}"
        assert "min relay fee not met" in _reason(res), f"{label}: rejected, but not for the fee: {res}"
        print(f"\n{label} one-photon-under: size={len(under.serialize())}B fee={floor - 1} -> {_reason(res)}")

        ok = node.accepts(at_floor.serialize().hex())
        assert ok.get("allowed") is True, f"{label}: node REJECTED a tx at exactly its floor: {ok}"
        print(f"{label} at-floor:          size={len(at_floor.serialize())}B fee={floor} -> accepted")
        return
    raise AssertionError(f"{label}: no build landed exactly on its own relay floor")


def test_covenant_cancel_boundary_is_the_nodes_own_floor(node):
    """Case 5a. Cancel is the ONLY hard revocation — an unrelayable one is silent loss."""
    _covenant_boundary(
        node,
        lambda src, maker, pkh, fee, policy: build_covenant_cancel_tx(
            covenant_source_tx=src,
            covenant_vout=0,
            maker_key=maker,
            refund_pkh=pkh,
            fee=fee,
            fee_policy=policy,
        ),
        "v3 covenant cancel",
    )


def test_covenant_refund_boundary_is_the_nodes_own_floor(node):
    """Case 5b. The CLTV branch, which only becomes final at/after ``_EXPIRY``.

    Mines up to the expiry first: before it, the node refuses a refund as
    ``non-final``, and a rejection that says ``non-final`` would prove nothing about
    the fee. This case has to be able to distinguish the two reasons, so it removes
    the other one.
    """
    height = int(node.cli("getblockcount"))
    if height <= _EXPIRY:
        node.mine(_EXPIRY - height + 1)
    assert int(node.cli("getblockcount")) > _EXPIRY, "the refund branch is non-final until past the expiry height"
    _covenant_boundary(
        node,
        lambda src, maker, pkh, fee, policy: build_covenant_refund_tx(
            covenant_source_tx=src,
            covenant_vout=0,
            maker_key=maker,
            refund_pkh=pkh,
            fee=fee,
            fee_policy=policy,
        ),
        "v3 covenant refund",
    )


def test_the_reject_reason_is_about_the_fee_and_nothing_else(node):
    """A rejection that says something else would make every case above meaningless.

    Same transaction, two fees: one comfortably above the floor (accepted, so the
    script, the ref and the locktime are all fine) and one below it (refused). The
    only difference is the fee, so the reason has to be the fee.
    """
    rate = _node_rate(node)
    policy = DeadlineFeePolicy(relay_fee_per_kb=rate * 1000)
    maker = PrivateKey()
    reserved = _covenant(node, maker)
    pkh = maker.public_key().hash160()

    fat = build_covenant_cancel_tx(
        covenant_source_tx=reserved, covenant_vout=0, maker_key=maker, refund_pkh=pkh, fee=20_000_000
    )
    assert node.accepts(fat.serialize().hex()).get("allowed") is True, "the script itself must be spendable"

    thin = build_covenant_cancel_tx(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        refund_pkh=pkh,
        fee=policy.min_relay_fee(190) // 2,
        fee_policy=_PERMISSIVE,
    )
    res = node.accepts(thin.serialize().hex())
    assert res.get("allowed") is False
    assert "min relay fee not met" in _reason(res), f"the same script, refused for a NON-fee reason: {res}"
    print(f"\nsame covenant, halved fee -> {_reason(res)}")


def test_no_case_here_touched_anything_but_regtest(node):
    """Belt-and-braces: assert the chain, out loud, in an assertion that can fail."""
    assert node.cli("getblockchaininfo")["chain"] == "regtest"
    assert json.loads(json.dumps(node.cli("getmempoolinfo")))["effective_minrelaytxfee"] == 0.1
