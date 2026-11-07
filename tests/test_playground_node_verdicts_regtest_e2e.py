"""The Radiant Playground's sandbox verdicts, put to a real Radiant node.

The playground (``docs/inspect_static/playground/playground.py``) checks a visitor's
transaction against rules it does not run Radiant's interpreter for. Several of those rules
(the singleton sibling rule, the FT covenant's output count, the delegate burn, hybrid keys)
were decided by reading Radiant Core's source. This module builds each of those shapes on a
regtest node with real keys and coins, submits the SAME bytes to the node
(``testmempoolaccept``) and to a fresh ``SandboxChain`` holding the same prevouts (read back
from the node), and pins both verdicts.

Each pin says what was measured on the date it was written. A row where the two disagree is
marked ``DISAGREE`` in :data:`VERDICTS`: if the sandbox is changed to match the node, its pin
fails and the row must be updated, so a fixed disagreement cannot stay listed as open.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Throwaway container with its
own name, no real value, no PoW. Node at mainnet's relay floor (the harness asserts it).

Operator-run, not in ``.github/workflows/integration.yml`` or ``task test-regtest``: it pins
the sandbox of a docs page against the node rather than a library path, and it was written to
settle a review's open questions once. Add it to the per-push lane if the sandbox's rules
start changing often.

Run: ``RADIANT_REGTEST=1 pytest -o "addopts=" -m integration -q -s tests/test_playground_node_verdicts_regtest_e2e.py``
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from test_container_regtest_e2e import _mint_nft, _reveal_unlock
from test_ft_airdrop_regtest_e2e import _deploy_ft
from test_htlc_regtest_e2e import _IMAGE, _p2pkh_unlock, _pay_to_spk, _RegtestNode, _src

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.script import build_ft_locking_script, build_nft_locking_script
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.hash import hash160
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import encode_pushdata, to_unlock_script_template
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

pytestmark = pytest.mark.integration

_PLAYGROUND = Path(__file__).resolve().parents[1] / "docs" / "inspect_static" / "playground"

#: This module's own container, named per process: ``_RegtestNode.start`` force-removes its
#: container by name, so a shared name would let two runs destroy each other's node.
_CONTAINER = f"pyrxd-regtest-playground-verdicts-{os.getpid()}"

_FEE = 20_000_000  # 0.2 RXD: covers ~2 kB at the mainnet floor; every tx here is under 1 kB
_CARRIER = 1_000_000  # photons on an extra ref-carrying output
_FUND = 300_000_000  # a plain coin, enough for a fee and a carrier

#: ``shape -> (sandbox verdict, node verdict)``, as measured. A sandbox verdict is
#: ``"accepted"``, ``"accepted, warn <rules>"`` or ``"refused <rule>"``; a node verdict is
#: ``"accepted"`` or ``"refused <reject-reason>"``. Rows the two disagree on carry DISAGREE.
VERDICTS: dict[str, tuple[str, str]] = {}

#: The node's reject reasons, as measured. A refusal is pinned to its reason, so a shape that
#: starts failing for some other cause (a fee, a missing input) cannot pass as the rule under test.
_REF_RULES = "bad-txns-inputs-outputs-invalid-transaction-reference-operations"
_COVENANT_COUNT = "Script failed an OP_NUMEQUALVERIFY operation"
_STRICTENC = "Public key is neither compressed or uncompressed"


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def node():
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_IMAGE} image not available")
    n = _RegtestNode(container=_CONTAINER)
    n.start()
    try:
        yield n
    finally:
        n.stop()


@pytest.fixture(scope="module", autouse=True)
def _print_table():
    yield
    if VERDICTS:
        print("\n\nshape | sandbox | node")
        for shape, (sandbox, verdict) in VERDICTS.items():
            print(f"{shape} | {sandbox} | {verdict}")


@pytest.fixture(scope="module")
def pg():
    sys.path.insert(0, str(_PLAYGROUND))
    try:
        spec = importlib.util.spec_from_file_location("playground", _PLAYGROUND / "playground.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["playground"] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.path.remove(str(_PLAYGROUND))
        sys.modules.pop("playground", None)


# --------------------------------------------------------------------------- helpers


def _p2pkh(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"


def _plain(node, key: PrivateKey | None = None, value: int = _FUND) -> dict:
    """A confirmed plain P2PKH coin of ``value`` under ``key`` (fresh if not given)."""
    key = key or PrivateKey()
    spk = _p2pkh(key.public_key().hash160())
    return {"txid": _pay_to_spk(node, spk, value), "vout": 0, "value": value, "script": spk, "key": key}


def _input(coin: dict, unlock=None) -> TransactionInput:
    """Spend ``coin``; ``unlock`` defaults to a P2PKH signature by ``coin['key']``.

    NFT, FT and ``d0 <ref> OP_DROP`` + P2PKH scripts all end in a P2PKH, so the same unlock serves.
    """
    return TransactionInput(
        source_transaction=_src(coin["txid"], coin["vout"], coin["script"], coin["value"]),
        source_txid=coin["txid"],
        source_output_index=coin["vout"],
        unlocking_script_template=unlock or _p2pkh_unlock(coin["key"]),
    )


def _tx(inputs: list[TransactionInput], outputs: list[tuple[bytes, int]]) -> Transaction:
    tx = Transaction(tx_inputs=inputs, tx_outputs=[TransactionOutput(Script(s), v) for s, v in outputs])
    tx.sign()
    return tx


def _node_verdict(node, tx: Transaction) -> str:
    res = node.accepts(tx.serialize().hex())
    if res.get("allowed") is True:
        return "accepted"
    return f"refused {res.get('reject-reason')}"


def _sandbox_verdict(node, pg, tx: Transaction) -> str:
    """Submit ``tx``'s exact bytes to a fresh sandbox chain that holds its prevouts.

    Each prevout's script and value are read back from the node, not from what the test built,
    so the sandbox judges the same coins the node does.
    """
    chain = pg.SandboxChain()
    for txin in tx.inputs:
        prev = node.cli("getrawtransaction", txin.source_txid, "true")
        out = prev["vout"][txin.source_output_index]
        script = bytes.fromhex(out["scriptPubKey"]["hex"])
        value = round(out["value"] * 100_000_000)
        key = (txin.source_txid, txin.source_output_index)
        chain.utxos[key] = pg.Coin(txin.source_txid, txin.source_output_index, value, script, None, 1)
    try:
        acc = chain.submit(tx.serialize())
    except pg.SandboxRejected as exc:
        return f"refused {exc.rule}: {exc}"
    warns = sorted({c.rule for c in acc.checks if c.status != "pass"})
    return "accepted" + (f", warn {' '.join(warns)}" if warns else "")


def _judge(node, pg, shape: str, tx: Transaction) -> tuple[str, str]:
    sandbox, verdict = _sandbox_verdict(node, pg, tx), _node_verdict(node, tx)
    agree = sandbox.startswith("accepted") == (verdict == "accepted")
    VERDICTS[shape] = (sandbox, verdict)
    print(f"\nVERDICT | {shape} | sandbox: {sandbox} | node: {verdict}{'' if agree else ' | DISAGREE'}")
    return sandbox, verdict


def _send(node, tx: Transaction, *, what: str) -> str:
    res = node.accepts(tx.serialize().hex())
    assert res.get("allowed") is True, f"{what} REJECTED: {res}"
    txid = str(node.cli("sendrawtransaction", tx.serialize().hex()))
    node.mine(1)
    return txid


def _nft(node) -> dict:
    minted = _mint_nft(node, GlyphMetadata(protocol=[GlyphProtocol.NFT], name="PLAYGROUND-VERDICT"))
    return {
        "txid": minted["reveal_txid"],
        "vout": minted["vout"],
        "value": minted["value"],
        "script": minted["script"],
        "key": minted["key"],
        "ref": minted["ref"],
    }


def _normal_push(ref: GlyphRef, pkh: bytes) -> bytes:
    """``OP_PUSHINPUTREF <ref> OP_DROP`` + P2PKH: holds ``ref`` as a normal ref."""
    return b"\xd0" + ref.to_bytes() + b"\x75" + _p2pkh(pkh)


def _fee_out(fee: dict, minus: int = 0) -> tuple[bytes, int]:
    return (fee["script"], fee["value"] - _FEE - minus)


# --------------------------------------------------------------------------- 1-3, 9: singleton refs


def test_h1_singleton_beside_a_normal_push_in_another_output(node, pg):
    """H1 (review F1). Honest pair: the same NFT moved to one output."""
    nft, fee = _nft(node), _plain(node)
    friend = PrivateKey().public_key().hash160()
    bad = _tx(
        [_input(nft), _input(fee)],
        [
            (build_nft_locking_script(Hex20(friend), nft["ref"]), nft["value"]),
            (_normal_push(nft["ref"], fee["key"].public_key().hash160()), _CARRIER),
            _fee_out(fee, _CARRIER),
        ],
    )
    sandbox, verdict = _judge(node, pg, "H1 d8 in out0 + d0 same ref in out1", bad)
    assert sandbox.startswith("refused refs"), sandbox
    assert _REF_RULES in verdict, verdict

    honest = _tx(
        [_input(nft), _input(fee)], [(build_nft_locking_script(Hex20(friend), nft["ref"]), nft["value"]), _fee_out(fee)]
    )
    assert _judge(node, pg, "H1 honest: NFT moved to one output", honest) == ("accepted", "accepted")


def test_h2_two_outputs_each_pushing_normal_then_singleton(node, pg):
    """H2 (review F1). The node had never ruled on this shape before this test."""
    nft, fee = _nft(node), _plain(node)
    pkh = fee["key"].public_key().hash160()
    both = b"\xd0" + nft["ref"].to_bytes() + b"\x75\xd8" + nft["ref"].to_bytes() + b"\x75" + _p2pkh(pkh)
    bad = _tx([_input(nft), _input(fee)], [(both, nft["value"]), (both, _CARRIER), _fee_out(fee, _CARRIER)])
    sandbox, verdict = _judge(node, pg, "H2 two outputs each d0 then d8 of the same ref", bad)
    assert sandbox.startswith("refused refs"), sandbox
    assert _REF_RULES in verdict, verdict

    one = _tx([_input(nft), _input(fee)], [(both, nft["value"]), _fee_out(fee)])
    sandbox, verdict = _judge(node, pg, "H2 honest-ish: ONE output pushing d0 then d8", one)
    assert sandbox == "accepted", sandbox
    assert verdict == "accepted", verdict


def test_one_output_pushing_singleton_and_normal_of_the_same_ref(node, pg):
    """Shape 3. One output, d8 then d0 of one ref: the sibling rule is about OTHER outputs."""
    nft, fee = _nft(node), _plain(node)
    pkh = fee["key"].public_key().hash160()
    mixed = b"\xd8" + nft["ref"].to_bytes() + b"\x75\xd0" + nft["ref"].to_bytes() + b"\x75" + _p2pkh(pkh)
    tx = _tx([_input(nft), _input(fee)], [(mixed, nft["value"]), _fee_out(fee)])
    sandbox, verdict = _judge(node, pg, "3 one output d8 + d0 of the same ref", tx)
    assert sandbox == "accepted", sandbox
    assert verdict == "accepted", verdict


def test_a_split_singleton_cannot_be_promoted_back(node, pg):
    """Shape 4. Split an NFT into two normal-ref outputs, then try to make each a singleton."""
    nft, fee = _nft(node), _plain(node)
    key = fee["key"]
    pkh = key.public_key().hash160()
    split = _tx(
        [_input(nft), _input(fee)],
        [
            (_normal_push(nft["ref"], pkh), nft["value"]),
            (_normal_push(nft["ref"], pkh), _CARRIER),
            _fee_out(fee, _CARRIER),
        ],
    )
    sandbox, verdict = _judge(node, pg, "4a split: NFT into two d0 outputs", split)
    assert sandbox == "accepted, warn refs", sandbox
    assert verdict == "accepted", verdict
    split_txid = _send(node, split, what="split")

    halves = [
        {"txid": split_txid, "vout": 0, "value": nft["value"], "script": _normal_push(nft["ref"], pkh), "key": key},
        {"txid": split_txid, "vout": 1, "value": _CARRIER, "script": _normal_push(nft["ref"], pkh), "key": key},
    ]
    fee2 = _plain(node)
    nft_script = build_nft_locking_script(Hex20(pkh), nft["ref"])
    one = _tx([_input(halves[0]), _input(fee2)], [(nft_script, halves[0]["value"]), _fee_out(fee2)])
    sandbox, verdict = _judge(node, pg, "4b promote: one d0 coin into a d8 output", one)
    assert sandbox.startswith("refused refs"), sandbox
    assert _REF_RULES in verdict, verdict

    two = _tx(
        [_input(halves[0]), _input(halves[1]), _input(fee2)],
        [(nft_script, halves[0]["value"]), (nft_script, halves[1]["value"]), _fee_out(fee2)],
    )
    sandbox, verdict = _judge(node, pg, "4c promote: both d0 coins into two d8 outputs", two)
    assert sandbox.startswith("refused refs"), sandbox
    assert _REF_RULES in verdict, verdict

    keep = _tx([_input(halves[0]), _input(fee2)], [(_normal_push(nft["ref"], pkh), halves[0]["value"]), _fee_out(fee2)])
    assert _judge(node, pg, "4 honest: a d0 coin kept as d0", keep) == ("accepted, warn scripts", "accepted")


def test_an_nft_ref_carried_into_an_ft_output(node, pg):
    """Shape 9 (review F12, NFT form). NFT input; an FT-shaped output carries the NFT's ref.

    The node ACCEPTS. The NFT is gone (no output keeps its singleton) and an FT-shaped output now
    holds its ref. The sandbox used to refuse this; it now accepts it and warns on both counts.
    """
    nft, fee = _nft(node), _plain(node)
    pkh = Hex20(fee["key"].public_key().hash160())
    tx = _tx(
        [_input(nft), _input(fee)],
        [(build_ft_locking_script(pkh, nft["ref"]), 50_000_000), _fee_out(fee, 50_000_000 - nft["value"])],
    )
    sandbox, verdict = _judge(node, pg, "9 NFT ref into an FT-shaped output", tx)
    assert sandbox == "accepted, warn ft refs", sandbox
    assert verdict == "accepted", verdict


# --------------------------------------------------------------------------- 5-6: FT outputs


def test_f2_an_extra_non_ft_output_pushing_the_ft_ref(node, pg):
    """Shape 5 (review F2). Honest pair: the FT moved whole, with no extra output."""
    ft, fee = _deploy_ft(node), _plain(node)
    coin = {"txid": ft.txid, "vout": ft.vout, "value": ft.value, "script": ft.script, "key": ft.key}
    pkh = fee["key"].public_key().hash160()
    bad = _tx(
        [_input(coin), _input(fee)],
        [(ft.script, ft.value), (_normal_push(ft.ref, pkh), _CARRIER), _fee_out(fee, _CARRIER)],
    )
    sandbox, verdict = _judge(node, pg, "5 F2 FT spend + a non-FT output pushing its ref", bad)
    assert sandbox.startswith("refused ft"), sandbox
    assert _COVENANT_COUNT in verdict, verdict

    honest = _tx([_input(coin), _input(fee)], [(ft.script, ft.value), _fee_out(fee)])
    assert _judge(node, pg, "5 honest: FT moved whole", honest) == ("accepted", "accepted")


def test_f12_an_ft_output_whose_ref_no_ft_input_or_deploy_provides(node, pg):
    """Shape 6 (review F12). A plain coin's outpoint becomes the ref of an FT-shaped output.

    No FT input, no FT commit: the FT script appears with no deploy behind it.

    The node ACCEPTS. The FT script is a covenant on SPENDING, so nothing in consensus checks how
    an FT-shaped output was created; a normal ref minted from a spent outpoint is allowed in any
    output. The sandbox used to refuse this; it now accepts it with an ``ft`` warning.
    """
    fee = _plain(node)
    pkh = Hex20(fee["key"].public_key().hash160())
    ref = GlyphRef(txid=fee["txid"], vout=fee["vout"])
    tx = _tx([_input(fee)], [(build_ft_locking_script(pkh, ref), 50_000_000), _fee_out(fee, 50_000_000)])
    sandbox, verdict = _judge(node, pg, "6 F12 FT output minted from a plain outpoint", tx)
    assert sandbox == "accepted, warn ft", sandbox
    assert verdict == "accepted", verdict


# --------------------------------------------------------------------------- 7: delegate commit


def _delegate_reveal(node, *, burn: bool) -> Transaction:
    """The sandbox's F3 shape: a commit behind a delegate prefix whose delegate ref is minted from
    the commit transaction's own input, then a reveal with or without the delegate burn."""
    funding = _plain(node)
    owner = funding["key"]
    owner_pkh = Hex20(owner.public_key().hash160())
    builder = GlyphBuilder()
    commit_value = funding["value"] - _FEE
    commit = builder.prepare_commit(
        CommitParams(
            metadata=GlyphMetadata(protocol=[GlyphProtocol.NFT], name="PLAYGROUND-DELEGATE"),
            owner_pkh=owner_pkh,
            change_pkh=owner_pkh,
            funding_satoshis=commit_value,
            delegate_ref=GlyphRef(txid=funding["txid"], vout=funding["vout"]),
        )
    )
    commit_txid = _send(node, _tx([_input(funding)], [(commit.commit_script, commit_value)]), what="delegate commit")
    scripts = builder.prepare_reveal(
        RevealParams(
            commit_txid=commit_txid,
            commit_vout=0,
            commit_value=commit_value,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=owner_pkh,
            is_nft=True,
            commit_script=commit.commit_script,
        )
    )
    assert scripts.delegate_burn_script is not None
    held = {"txid": commit_txid, "vout": 0, "value": commit_value, "script": commit.commit_script, "key": owner}
    outs = [(scripts.locking_script, _CARRIER)]
    if burn:
        outs.append((scripts.delegate_burn_script, 0))
    outs.append((_p2pkh(owner_pkh), commit_value - _CARRIER - _FEE))
    return _tx([_input(held, _reveal_unlock(owner, scripts.scriptsig_suffix))], outs)


def test_f3_a_delegate_reveal_without_its_burn(node, pg):
    """Shape 7 (review F3). The sandbox does not run the delegate burn and says so with a warning.

    DISAGREE in verdict, by design: the sandbox ACCEPTS with a ``scripts`` warning that the
    burn was NOT evaluated (and a ``refs`` warning that the delegate ref is burned), the node
    REFUSES on the prefix's output count. The warnings are the sandbox's whole claim here.
    """
    sandbox, verdict = _judge(
        node, pg, "7 F3 delegate reveal WITHOUT the burn output", _delegate_reveal(node, burn=False)
    )
    assert sandbox == "accepted, warn refs scripts", sandbox
    assert _COVENANT_COUNT in verdict, verdict

    honest = _delegate_reveal(node, burn=True)
    # The refs warning is true here too: OP_REQUIREINPUTREF is not a push, so the burn consumes
    # the delegate ref, which is the point of a delegate burn.
    assert _judge(node, pg, "7 honest: delegate reveal WITH the burn output", honest) == (
        "accepted, warn refs scripts",
        "accepted",
    )


# --------------------------------------------------------------------------- 8: public-key encodings


def _spend_with_pub(node, key: PrivateKey, pub: bytes) -> Transaction:
    """Fund hash160(``pub``), then spend it with ``key``'s signature and ``pub`` pushed."""
    spk = _p2pkh(hash160(pub))
    coin = {"txid": _pay_to_spk(node, spk, _FUND), "vout": 0, "value": _FUND, "script": spk}

    def _u(tx, idx):
        sig = key.sign(tx.preimage(idx))
        return Script(encode_pushdata(sig + tx.inputs[idx].sighash.to_bytes(1, "little")) + encode_pushdata(pub))

    unlock = to_unlock_script_template(_u, lambda: 140)
    return _tx([_input(coin, unlock)], [(_p2pkh(key.public_key().hash160()), _FUND - _FEE)])


def test_f4_public_key_encodings(node, pg):
    """Shape 8 (review F4). Hybrid 06/07 refused; compressed 02/03 and uncompressed 04 accepted."""
    key = PrivateKey()
    point = key.public_key().serialize(compressed=False)
    hybrid = bytes([6 + (point[-1] & 1)]) + point[1:]
    sandbox, verdict = _judge(node, pg, f"8 F4 hybrid key (0x{hybrid[0]:02x})", _spend_with_pub(node, key, hybrid))
    assert sandbox.startswith("refused scripts"), sandbox
    assert _STRICTENC in verdict, verdict

    compressed = key.public_key().serialize()
    tx = _spend_with_pub(node, key, compressed)
    assert _judge(node, pg, f"8 honest: compressed key (0x{compressed[0]:02x})", tx) == ("accepted", "accepted")
    tx = _spend_with_pub(node, key, point)
    assert _judge(node, pg, "8 honest: uncompressed key (0x04)", tx) == ("accepted", "accepted")
