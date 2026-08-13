"""Tests for the cold swap-recovery core (:mod:`pyrxd.cli.swap_recovery`).

The negative security cases here ARE the point of the module. A preimage scraper that
matches on ``sha256(p) == H`` alone is exploitable: two swaps can share a hashlock, so a
transaction that merely *contains* a valid-looking ``p`` is not evidence that OUR swap's
counter-leg was claimed. Every refusal below corresponds to a way that could go wrong.

The read-only assertions are the other half: this toolkit's entire safety argument is
that it cannot broadcast, so that property is tested at the source level (imports and
call names), at the transport level (the ETH RPC allowlist), and at runtime (a client
whose ``broadcast`` detonates).
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.btc_wallet.taproot import BtcOutpoint, btc_txid_from_raw
from pyrxd.cli import swap_recovery as sr
from pyrxd.gravity.fee_policy import DeadlineFeePolicy
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import KeyMaterialError, ValidationError

# --------------------------------------------------------------------------- fixtures / builders

P = bytes.fromhex("11" * 32)
H = hashlib.sha256(P).digest()
OUR_FUNDING = BtcOutpoint(txid="aa" * 32, vout=1)
FOREIGN_FUNDING = BtcOutpoint(txid="bb" * 32, vout=0)
CONTRACT = "0xAbCd000000000000000000000000000000000001"
OTHER_CONTRACT = "0x9999000000000000000000000000000000000002"


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _segwit_tx(prevouts: list[BtcOutpoint], witnesses: list[list[bytes]]) -> bytes:
    """A minimal, structurally valid segwit transaction with the given inputs + witnesses."""
    body = (2).to_bytes(4, "little") + b"\x00\x01" + _varint(len(prevouts))
    for po in prevouts:
        body += po.prevout_bytes() + b"\x00" + (0xFFFFFFFD).to_bytes(4, "little")
    body += _varint(1) + (1000).to_bytes(8, "little") + _varint(1) + b"\x51"
    for w in witnesses:
        body += _varint(len(w))
        for item in w:
            body += _varint(len(item)) + item
    return body + (0).to_bytes(4, "little")


def _claim_tx(outpoint: BtcOutpoint = OUR_FUNDING, preimage: bytes = P) -> bytes:
    """A claim-shaped spend: signature, preimage, leaf script, control block."""
    return _segwit_tx([outpoint], [[b"\x01" * 64, preimage, b"\x20" + H + b"\x87", b"\xc0" + b"\x02" * 32]])


def _refund_tx(outpoint: BtcOutpoint = OUR_FUNDING) -> bytes:
    """A refund-shaped spend of the SAME outpoint: no 32-byte value hashes to H."""
    return _segwit_tx([outpoint], [[b"\x03" * 64, b"\x04" * 40, b"\xc0" + b"\x05" * 32]])


def _eth_tx(*, to: str = CONTRACT, calldata: bytes = b"", tx_hash: str = "0xfeed") -> dict:
    return {"hash": tx_hash, "to": to, "input": "0x" + calldata.hex()}


def _eth_log(*, address: str = CONTRACT, data: bytes = b"", tx_hash: str = "0xfeed") -> dict:
    return {"address": address, "data": "0x" + data.hex(), "topics": [], "transactionHash": tx_hash}


# --------------------------------------------------------------------------- BTC: happy path


def test_btc_claim_yields_the_preimage_with_full_provenance() -> None:
    raw = _claim_tx()
    rec = sr.recover_preimage_from_btc_claim(
        raw, hashlock=H, funding_outpoint=OUR_FUNDING, reported_txid=btc_txid_from_raw(raw)
    )
    assert rec.preimage_hex == P.hex()
    assert rec.counter_chain == "btc"
    assert rec.claim_txid == btc_txid_from_raw(raw)
    # All three checks must be recorded — the operator reads them.
    assert any("txid re-derived" in c for c in rec.provenance)
    assert any("funding outpoint" in c for c in rec.provenance)
    assert any("re-verified" in c for c in rec.provenance)


def test_btc_claim_scrapes_regardless_of_witness_position() -> None:
    # Match by CONTENT, never by offset (the C-PARSER lesson): p buried under padding
    # pushes in a different input must still be found.
    raw = _segwit_tx(
        [FOREIGN_FUNDING, OUR_FUNDING],
        [[b"\x07" * 33], [b"\x08" * 71, b"\x09" * 20, P, b"\x20" + H + b"\x87"]],
    )
    rec = sr.recover_preimage_from_btc_claim(raw, hashlock=H, funding_outpoint=OUR_FUNDING)
    assert rec.preimage_hex == P.hex()


# --------------------------------------------------------------------------- BTC: the refusals


def test_foreign_claim_sharing_our_hashlock_is_refused() -> None:
    """THE case this module exists for: a valid p, our H, someone else's outpoint.

    Nothing about the transaction is malformed — it carries a genuine preimage for our
    hashlock. Only the prevout bind separates it from our swap's real claim, so a
    scraper without that bind would hand an attacker-chosen transaction straight into
    ``build-claim``.
    """
    raw = _claim_tx(outpoint=FOREIGN_FUNDING)
    with pytest.raises(sr.ProvenanceRefused, match="does not spend this swap's funding outpoint"):
        sr.recover_preimage_from_btc_claim(raw, hashlock=H, funding_outpoint=OUR_FUNDING)


def test_refund_of_our_outpoint_yields_no_preimage() -> None:
    with pytest.raises(sr.PreimageNotRevealed, match="reveals no preimage"):
        sr.recover_preimage_from_btc_claim(_refund_tx(), hashlock=H, funding_outpoint=OUR_FUNDING)


def test_fetched_bytes_whose_txid_does_not_match_the_reported_spender_are_refused() -> None:
    raw = _claim_tx()
    with pytest.raises(sr.ProvenanceRefused, match="not the reported spender"):
        sr.recover_preimage_from_btc_claim(raw, hashlock=H, funding_outpoint=OUR_FUNDING, reported_txid="ff" * 32)


def test_random_32_byte_push_that_does_not_hash_to_h_fails_closed() -> None:
    raw = _segwit_tx([OUR_FUNDING], [[os.urandom(32), os.urandom(32), os.urandom(32)]])
    with pytest.raises(sr.PreimageNotRevealed):
        sr.recover_preimage_from_btc_claim(raw, hashlock=H, funding_outpoint=OUR_FUNDING)


def test_unparseable_claim_bytes_are_refused_not_partially_parsed() -> None:
    with pytest.raises(sr.ProvenanceRefused, match="unparseable"):
        sr.recover_preimage_from_btc_claim(_claim_tx()[:20], hashlock=H, funding_outpoint=OUR_FUNDING)


def test_scraper_returning_a_non_matching_value_is_caught_by_the_independent_recheck(monkeypatch) -> None:
    # Defence in depth: if the scraper ever regressed and returned something that does
    # not open the lock, the last gate before p is printed must still refuse it.
    monkeypatch.setattr(sr, "scrape_secret", lambda raw, h: b"\x00" * 32)
    with pytest.raises(sr.ProvenanceRefused, match="does not hash to the swap's hashlock"):
        sr.recover_preimage_from_btc_claim(_claim_tx(), hashlock=H, funding_outpoint=OUR_FUNDING)


def test_hashlock_must_be_32_bytes() -> None:
    with pytest.raises(ValidationError, match="hashlock must be 32 bytes"):
        sr.recover_preimage_from_btc_claim(_claim_tx(), hashlock=b"\x00", funding_outpoint=OUR_FUNDING)


# --------------------------------------------------------------------------- ETH: happy + refusals


def test_eth_claim_calldata_yields_the_preimage() -> None:
    rec = sr.recover_preimage_from_eth_claim(
        hashlock=H, contract_address=CONTRACT, claim_tx=_eth_tx(calldata=b"\xde\xad\xbe\xef" + P)
    )
    assert rec.preimage_hex == P.hex()
    assert rec.source == "eth_claim_calldata"


def test_eth_claim_log_data_yields_the_preimage_when_the_call_is_nested() -> None:
    # A wrapper/multicall means `to` is not our contract, but a log emitted BY our
    # per-swap contract in the same tx still binds the artifact to this swap.
    rec = sr.recover_preimage_from_eth_claim(
        hashlock=H,
        contract_address=CONTRACT,
        claim_tx=_eth_tx(to=OTHER_CONTRACT, calldata=b"\x00" * 8),
        logs=[_eth_log(data=P)],
    )
    assert rec.preimage_hex == P.hex()
    assert rec.source == "eth_claim_log_data"


def test_eth_preimage_in_a_foreign_contracts_log_is_never_scanned() -> None:
    """A decoy log from ANOTHER contract carrying a valid p must not be reachable."""
    with pytest.raises(sr.ProvenanceRefused, match="neither calls nor emitted a log"):
        sr.recover_preimage_from_eth_claim(
            hashlock=H,
            contract_address=CONTRACT,
            claim_tx=_eth_tx(to=OTHER_CONTRACT),
            logs=[_eth_log(address=OTHER_CONTRACT, data=P)],
        )


def test_eth_log_from_a_different_transaction_is_not_scanned() -> None:
    with pytest.raises(sr.ProvenanceRefused, match="neither calls nor emitted a log"):
        sr.recover_preimage_from_eth_claim(
            hashlock=H,
            contract_address=CONTRACT,
            claim_tx=_eth_tx(to=OTHER_CONTRACT, tx_hash="0xaaaa"),
            logs=[_eth_log(data=P, tx_hash="0xbbbb")],
        )


def test_eth_tx_hash_mismatch_is_refused() -> None:
    with pytest.raises(sr.ProvenanceRefused, match="not the requested"):
        sr.recover_preimage_from_eth_claim(
            hashlock=H, contract_address=CONTRACT, claim_tx=_eth_tx(calldata=P), reported_tx_hash="0xzzzz"
        )


def test_eth_refund_reveals_no_preimage() -> None:
    with pytest.raises(sr.PreimageNotRevealed, match="reveals no preimage"):
        sr.recover_preimage_from_eth_claim(
            hashlock=H, contract_address=CONTRACT, claim_tx=_eth_tx(calldata=b"\x59\x0e\x1a\xe3")
        )


def test_eth_address_comparison_is_checksum_case_insensitive() -> None:
    rec = sr.recover_preimage_from_eth_claim(
        hashlock=H, contract_address=CONTRACT.lower(), claim_tx=_eth_tx(to=CONTRACT.upper(), calldata=P)
    )
    assert rec.preimage_hex == P.hex()


def test_eth_requires_a_32_byte_hashlock() -> None:
    with pytest.raises(ValidationError, match="hashlock must be 32 bytes"):
        sr.recover_preimage_from_eth_claim(hashlock=b"\x00", contract_address=CONTRACT, claim_tx=_eth_tx(calldata=P))


def test_eth_requires_a_contract_address() -> None:
    with pytest.raises(ValidationError, match="contract_address is required"):
        sr.recover_preimage_from_eth_claim(hashlock=H, contract_address="", claim_tx=_eth_tx(calldata=P))


# --------------------------------------------------------------------------- READ-ONLY enforcement

_MODULES = [
    Path(sr.__file__),
    Path(sr.__file__).with_name("swap_recovery_cmds.py"),
]

_BROADCAST_SHAPED = {
    "broadcast",
    "broadcast_transaction",
    "push_tx",
    "pushtx",
    "send_raw",
    "send_raw_transaction",
    "send_transaction",
    "sendrawtransaction",
    "submit_transaction",
}


def _trees() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text())) for p in _MODULES]


def test_module_graph_imports_no_broadcaster_or_coordinator() -> None:
    """No ``Broadcaster``/``Coordinator`` — and no key-holding leg — is imported by name.

    Scoped to the DIRECT imports of the cold modules, which is the property this code
    controls. A fully transitive assertion is not expressible on this tree and would be
    a false comfort: the brief's own reuse list (``btc_wallet.taproot.scrape_secret``,
    ``gravity.htlc_spend``) forces ``pyrxd.btc_wallet.__init__`` and
    ``pyrxd.gravity.__init__`` into ``sys.modules``, and BOTH of those re-export
    broadcaster symbols (``BitcoinCoreBroadcaster``, ``RadiantBroadcaster``). What is
    enforceable, and enforced here plus by the two tests below, is that the cold path
    never NAMES, holds, or calls one.
    """
    forbidden_modules = ("swap_coordinator", "radiant_leg", "eth_leg", "htlc_leg", "network.bitcoin", "maker")
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not any(bad in mod for bad in forbidden_modules), f"{path.name} imports from {mod}"
                names = [a.name for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            else:
                continue
            for name in names:
                assert "Broadcaster" not in name, f"{path.name} imports {name}"
                assert "Coordinator" not in name, f"{path.name} imports {name}"


def _calls_by_function(tree: ast.Module) -> list[tuple[str, ast.Call]]:
    out: list[tuple[str, ast.Call]] = []
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.extend((fn.name, n) for n in ast.walk(fn) if isinstance(n, ast.Call))
    return out


def _callee_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return ""


def test_no_broadcast_shaped_call_occurs_on_any_path() -> None:
    for path, tree in _trees():
        for fn_name, call in _calls_by_function(tree):
            name = _callee_name(call)
            assert name not in _BROADCAST_SHAPED, f"{path.name}::{fn_name} calls {name}()"


def test_the_only_http_post_is_the_allowlisted_eth_rpc_reader() -> None:
    """Ethereum JSON-RPC is POST-only, so the write surface is closed by allowlist instead.

    A literal "no POST anywhere" is not achievable for an ETH read — there is no GET
    transport for ``eth_getLogs``. The equivalent guarantee is that exactly one function
    may POST, and that function refuses any method outside
    :data:`ETH_READ_ONLY_RPC_METHODS` before it touches the session.
    """
    posts = [
        (path.name, fn)
        for path, tree in _trees()
        for fn, call in _calls_by_function(tree)
        if _callee_name(call) == "post"
    ]
    assert posts == [("swap_recovery.py", "eth_rpc_read")], posts


def test_eth_rpc_allowlist_contains_no_write_method() -> None:
    for method in sr.ETH_READ_ONLY_RPC_METHODS:
        assert method.startswith(("eth_get", "eth_block", "eth_chain")), method
    assert "eth_sendRawTransaction" not in sr.ETH_READ_ONLY_RPC_METHODS


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["eth_sendRawTransaction", "eth_sendTransaction", "personal_sendTransaction"])
async def test_eth_rpc_read_refuses_a_write_method_without_touching_the_session(method: str) -> None:
    session = MagicMock()
    session.post = MagicMock(side_effect=AssertionError("the session must never be touched for a write method"))
    with pytest.raises(ValidationError, match="not one of this toolkit's read-only RPC methods"):
        await sr.eth_rpc_read(session, "http://localhost:8545", method, [])
    session.post.assert_not_called()


# --------------------------------------------------------------------------- recovery-file parsing


def _keys_file(tmp_path: Path, **extra) -> Path:
    taker, maker = PrivateKey(), PrivateKey()
    doc = {
        "hashlock_H": H.hex(),
        "rxd_covenant_spk": "76a914" + "11" * 20 + "88ac",
        "t_rxd_blocks": 20,
        "rxd_network": "bc",
        "preimage_p_hex": "de" * 32,
        "taker_rxd_wif": taker.wif(),
        "maker_rxd_wif": maker.wif(),
    }
    doc.update(extra)
    p = tmp_path / "keys.json"
    # 0600, as scripts/_dust_swap_shared.atomic_write_mode_600 writes it. A recovery
    # file holding both counterparties' WIFs at umask mode is refused by
    # load_recovery_json — asserted directly below, not modelled by accident here.
    p.write_text(json.dumps(doc))
    p.chmod(0o600)
    return p


def test_extras_never_surface_the_files_preimage() -> None:
    # p from the FILE is not a legitimate source (it may be a pre-reveal secret on a
    # maker's host), so it must not appear in the parsed extras at all.
    with __import__("tempfile").TemporaryDirectory() as d:
        extras = sr.parse_recovery_extras(_keys_file(Path(d)))
    assert "de" * 32 not in repr(extras)
    assert not any("preimage" in f for f in extras.__dataclass_fields__)


def test_extras_pick_up_the_newer_locator_fields(tmp_path: Path) -> None:
    # The three fields the harnesses were changed to persist alongside this toolkit.
    f = _keys_file(
        tmp_path,
        btc_funding_outpoint="cc" * 32 + ":3",
        eth_contract_address=CONTRACT,
        rxd_covenant_amount=100_000,
        asset_ft_amount=500,
    )
    extras = sr.parse_recovery_extras(f)
    assert extras.btc_funding_outpoint == "cc" * 32 + ":3"
    assert extras.eth_contract_address == CONTRACT
    assert extras.rxd_covenant_amount == 100_000
    assert extras.asset_ft_amount == 500


def test_extras_default_to_none_on_a_legacy_file(tmp_path: Path) -> None:
    # Files written before the harness change carry none of it; the CLI must ask for the
    # locator with a flag rather than crashing on a file it can still otherwise read.
    extras = sr.parse_recovery_extras(_keys_file(tmp_path))
    assert extras.btc_funding_outpoint is None
    assert extras.eth_contract_address is None
    assert extras.rxd_covenant_amount is None


def test_covenant_pkhs_from_wifs_never_leak_the_wif(tmp_path: Path) -> None:
    f = _keys_file(tmp_path)
    taker, maker = sr.covenant_pkhs(f)
    assert len(taker) == 20 and len(maker) == 20
    doc = json.loads(f.read_text())
    assert taker == bytes(PrivateKey(doc["taker_rxd_wif"]).public_key().hash160())


def test_a_malformed_wif_in_the_recovery_file_is_never_echoed(tmp_path: Path) -> None:
    """The sink the audit reproduced: ``covenant_pkhs`` -> ``_pkh_from_wif`` ->
    ``PrivateKey(wif)`` -> ``base58``, whose ``ValueError`` escaped ``_run`` (which
    catches only ``NetworkError``/``OSError``) to the CLI boundary's
    ``cause: {exc}``. One out-of-alphabet character — a line wrap, a stray space,
    an ``O``/``I``/``l`` typo — published 51 of a 52-character key."""
    good = PrivateKey().wif()
    typo = good[:20] + "0" + good[21:]  # '0' is not in the base58 alphabet
    f = _keys_file(tmp_path, taker_rxd_wif=typo)

    with pytest.raises(KeyMaterialError) as exc:
        sr.covenant_pkhs(f)

    node: BaseException | None = exc.value
    while node is not None:
        rendered = f"{node}{node.args!r}"
        for start in range(len(good) - 8):
            assert good[start : start + 8] not in rendered
            assert typo[start : start + 8] not in rendered
        node = node.__cause__ or node.__context__


def test_covenant_pkhs_accept_explicit_overrides(tmp_path: Path) -> None:
    f = _keys_file(tmp_path)
    taker, maker = sr.covenant_pkhs(f, taker_pkh_hex="ab" * 20, maker_pkh_hex="cd" * 20)
    assert taker == bytes.fromhex("ab" * 20)
    assert maker == bytes.fromhex("cd" * 20)


def test_covenant_pkhs_explain_themselves_when_a_two_host_file_lacks_the_peer_key(tmp_path: Path) -> None:
    p = tmp_path / "local.json"
    p.write_text(json.dumps({"hashlock_H": H.hex(), "maker_rxd_wif": PrivateKey().wif()}))
    p.chmod(0o600)
    with pytest.raises(ValidationError, match="--taker-pkh"):
        sr.covenant_pkhs(p)


def test_parse_outpoint_rejects_garbage() -> None:
    with pytest.raises(ValidationError, match="must be 'txid:vout'"):
        sr.parse_outpoint("nope")
    with pytest.raises(ValidationError, match="vout must be an integer"):
        sr.parse_outpoint("aa" * 32 + ":x")


# --------------------------------------------------------------------------- Radiant reads


class _NoBroadcastClient:
    """An ElectrumX stand-in whose ``broadcast`` detonates, and that records every call."""

    def __init__(self, utxos: dict[str, list[UtxoRecord]], tip: int, history: list | None = None) -> None:
        self._utxos = utxos
        self._tip = tip
        self._history = history or []
        self.calls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def get_utxos(self, sh):
        self.calls.append("get_utxos")
        return self._utxos.get(sh, [])

    async def get_tip_height(self):
        self.calls.append("get_tip_height")
        return self._tip

    async def get_history(self, sh):
        self.calls.append("get_history")
        return self._history

    async def broadcast(self, raw):  # pragma: no cover - the assertion is that it never runs
        raise AssertionError("the cold recovery toolkit must never broadcast")


COV_SPK = "76a914" + "22" * 20 + "88ac"


@pytest.mark.asyncio
async def test_read_covenant_chain_state_measures_depth() -> None:
    sh = sr.electrumx_script_hash(COV_SPK)
    client = _NoBroadcastClient({sh: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=100)]}, tip=105)
    state = await sr.read_covenant_chain_state(client, COV_SPK)
    assert state.outpoint == "ab" * 32 + ":0"
    assert state.carrier_value == 100_000
    assert state.confirmations == 6  # 105 - 100 + 1
    assert "broadcast" not in client.calls


@pytest.mark.asyncio
async def test_read_covenant_chain_state_distinguishes_settled_from_never_funded() -> None:
    sh = sr.electrumx_script_hash(COV_SPK)
    with pytest.raises(ValidationError, match="already settled"):
        await sr.read_covenant_chain_state(_NoBroadcastClient({sh: []}, tip=10, history=[{"h": 1}]), COV_SPK)
    with pytest.raises(ValidationError, match="never funded"):
        await sr.read_covenant_chain_state(_NoBroadcastClient({sh: []}, tip=10), COV_SPK)


@pytest.mark.asyncio
async def test_read_covenant_chain_state_records_an_unreconcilable_tip_as_unresolved() -> None:
    """A funding height a re-read still puts above the tip yields ``depth_unresolved``.

    ``confirmations`` is derived as ``tip - height + 1``, so a height above the tip
    produces a NEGATIVE depth, and negative depth does not fail closed on the way out:
    ``build_cold_claim`` reports ``max(0, refund_csv - confirmations)`` blocks to the
    deadline, which for ``-4`` against a 20-block CSV reads as 24 — MORE headroom than the
    CSV total. So no depth is derived. Both real numbers are kept, and the flag makes every
    consumer treat the depth as unknown rather than as zero (which is equally a guess, just
    a smaller one).
    """
    sh = sr.electrumx_script_hash(COV_SPK)
    client = _NoBroadcastClient({sh: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=110)]}, tip=105)
    state = await sr.read_covenant_chain_state(client, COV_SPK)
    assert state.depth_unresolved is True
    assert state.funding_height == 110
    assert state.tip_height == 105
    assert state.confirmations == 0
    # The tip was re-read before that conclusion was drawn, not accepted on one look.
    assert client.calls.count("get_tip_height") == 1 + sr._TIP_REREAD_ATTEMPTS
    assert "broadcast" not in client.calls


def test_covenant_chain_state_refuses_impossible_depth_triples() -> None:
    """The three depth fields are one measurement; a chain cannot disagree with itself."""
    base = {"outpoint": "ab" * 32 + ":0", "carrier_value": 100_000}
    # Mined, but claiming zero depth.
    with pytest.raises(ValidationError, match="does not match tip"):
        sr.CovenantChainState(**base, funding_height=100, tip_height=105, confirmations=0)
    # In the mempool, but naming the block it is in.
    with pytest.raises(ValidationError, match="describes neither"):
        sr.CovenantChainState(**base, funding_height=None, tip_height=105, confirmations=6)
    # Mined one block above the tip — the shape the 0-conf fixture used to use.
    with pytest.raises(ValidationError, match="above the chain tip"):
        sr.CovenantChainState(**base, funding_height=100, tip_height=99, confirmations=0)
    # The two shapes a node really produces both construct.
    assert sr.CovenantChainState(**base, funding_height=100, tip_height=105, confirmations=6).confirmations == 6
    assert sr.CovenantChainState(**base, funding_height=None, tip_height=105, confirmations=0).confirmations == 0


@pytest.mark.asyncio
async def test_read_covenant_chain_state_refuses_an_ambiguous_covenant() -> None:
    sh = sr.electrumx_script_hash(COV_SPK)
    utxos = [
        UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=1, height=100),
        UtxoRecord(tx_hash="cd" * 32, tx_pos=0, value=2, height=100),
    ]
    with pytest.raises(ValidationError, match="cannot resolve a single covenant"):
        await sr.read_covenant_chain_state(_NoBroadcastClient({sh: utxos}, tip=105), COV_SPK)


# --------------------------------------------------------------------------- fee selection


def _utxo(value: int, tag: str = "ee") -> UtxoRecord:
    return UtxoRecord(tx_hash=tag * 32, tx_pos=0, value=value, height=10)


def test_fee_selection_takes_the_smallest_input_clearing_the_target() -> None:
    chosen = sr.select_fee_utxo(
        [_utxo(9_000_000, "aa"), _utxo(3_000_000, "bb"), _utxo(5_000_000, "cc")],
        floor=1_000_000,
        target=3_000_000,
        explicit=None,
    )
    assert chosen.value == 3_000_000


def test_fee_selection_falls_back_to_the_floor_rather_than_refusing() -> None:
    # Refusing a spend the node WOULD have accepted is how an operator loses the asset
    # to the counterparty's refund — the floor binds, the target is only a target.
    chosen = sr.select_fee_utxo([_utxo(2_000_000)], floor=1_000_000, target=3_000_000, explicit=None)
    assert chosen.value == 2_000_000


def test_fee_selection_refuses_below_the_relay_floor_and_says_why() -> None:
    with pytest.raises(ValidationError, match="no RBF and no CPFP"):
        sr.select_fee_utxo([_utxo(500)], floor=1_000_000, target=3_000_000, explicit=None)


def test_explicit_fee_utxo_must_actually_be_unspent() -> None:
    with pytest.raises(ValidationError, match="is not an unspent output"):
        sr.select_fee_utxo([_utxo(9_000_000, "aa")], floor=1, target=1, explicit="bb" * 32 + ":0")


def test_explicit_fee_utxo_is_honoured_even_when_it_is_not_the_default_pick() -> None:
    # Realistic floor/target: the overpay ceiling (audit B4) is a MULTIPLE of the requirement,
    # so the degenerate floor=target=1 this used to pass would make any real UTXO an "overpay".
    chosen = sr.select_fee_utxo(
        [_utxo(3_000_000, "aa"), _utxo(9_000_000, "bb")],
        floor=1_000_000,
        target=2_660_000,
        explicit="bb" * 32 + ":0",
    )
    assert chosen.value == 9_000_000


# --------------------------------------------------------------------------- cold spends


@pytest.fixture
def swap_setup():
    taker, maker, fee_key = PrivateKey(), PrivateKey(), PrivateKey()
    cov = build_htlc_covenant_rxd(
        amount=100_000,
        taker_pkh=bytes(taker.public_key().hash160()),
        maker_pkh=bytes(maker.public_key().hash160()),
        hashlock=H,
        refund_csv=20,
    )
    return cov, taker, maker, fee_key


def _chain(cov_conf: int) -> sr.CovenantChainState:
    """A covenant chain state a real node could actually report.

    ``cov_conf == 0`` means MEMPOOL, and a mempool UTXO has no funding height —
    that is the shape ``read_covenant_chain_state`` emits (``funding_height =
    int(u.height) if int(u.height) > 0 else None``). This helper used to hand
    back ``funding_height=100`` with ``tip_height=99`` for the 0-conf case: a
    covenant mined one block ABOVE the chain tip while simultaneously reporting
    zero depth. ``CovenantChainState`` now refuses that triple outright.
    """
    if cov_conf == 0:
        return sr.CovenantChainState(
            outpoint="ab" * 32 + ":0",
            carrier_value=100_000,
            funding_height=None,
            tip_height=100,
            confirmations=0,
        )
    return sr.CovenantChainState(
        outpoint="ab" * 32 + ":0",
        carrier_value=100_000,
        funding_height=100,
        tip_height=100 + cov_conf - 1,
        confirmations=cov_conf,
    )


def test_cold_claim_reports_everything_a_human_needs(swap_setup) -> None:
    cov, _taker, _maker, fee_key = swap_setup
    spend = sr.build_cold_claim(
        covenant=cov, chain=_chain(5), preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000)
    )
    assert spend.kind == "claim"
    assert bytes.fromhex(spend.raw_hex)  # decodes
    assert spend.blocks_to_deadline == 15  # 20 - 5
    assert spend.urgency_multiplier == 1.0  # 15 blocks out is beyond the 6-block horizon
    assert spend.relay_floor_photons == DeadlineFeePolicy().min_relay_fee(spend.size_bytes)
    assert spend.clears_floor is True
    assert len(spend.outputs) == 1
    assert spend.outputs[0]["pays"].startswith("TAKER holder script")
    assert spend.outputs[0]["scriptpubkey_hex"] == cov.taker_holder_script.hex()
    assert spend.to_dict()["broadcast"] is False


def test_cold_claim_applies_the_urgency_premium_as_the_deadline_closes(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    near = sr.build_cold_claim(
        covenant=cov, chain=_chain(18), preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000)
    )
    assert near.blocks_to_deadline == 2
    assert near.urgency_multiplier > 1.0
    assert near.target_photons > near.relay_floor_photons


def test_cold_claim_refuses_a_preimage_that_does_not_open_the_lock(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    with pytest.raises(ValidationError, match="does not hash to the covenant hashlock"):
        sr.build_cold_claim(
            covenant=cov, chain=_chain(5), preimage=b"\x00" * 32, fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000)
        )


def test_cold_claim_refuses_a_fee_input_below_the_relay_floor(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    with pytest.raises(ValidationError, match="below the required"):
        sr.build_cold_claim(covenant=cov, chain=_chain(5), preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(1000))


def test_cold_refund_refuses_an_immature_csv_by_default(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    with pytest.raises(ValidationError, match="not yet mature"):
        sr.build_cold_refund(covenant=cov, chain=_chain(5), fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000))


def test_cold_refund_can_be_prebuilt_before_maturity_and_says_so(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    spend = sr.build_cold_refund(
        covenant=cov, chain=_chain(5), fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000), allow_immature=True
    )
    assert spend.csv_mature is False
    assert spend.csv_confirmations == 5 and spend.csv_required == 20


def test_cold_refund_at_maturity_pays_the_maker_with_no_urgency_premium(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    spend = sr.build_cold_refund(covenant=cov, chain=_chain(20), fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000))
    assert spend.csv_mature is True
    assert spend.blocks_to_deadline is None
    assert spend.target_photons == spend.relay_floor_photons  # no premium on a refund
    assert spend.outputs[0]["scriptpubkey_hex"] == cov.maker_holder_script.hex()
    assert spend.outputs[0]["pays"].startswith("MAKER holder script")


# --------------------------------------------------------------------------- lagging tip / reorg
#
# ``read_covenant_chain_state`` makes TWO round trips and failover picks an endpoint PER
# CALL, so the tip can come from a lagging server and a reorg can land between the reads.
# That produced ``funding_height > tip_height``, which ``CovenantChainState`` refused —
# inside a constructor, ahead of ``--allow-unconfirmed``, on the cold-recovery path during
# a CSV race. These cover the whole shape, not just the constructor.


class _LaggingTipClient(_NoBroadcastClient):
    """Answers ``listunspent`` from a caught-up view and the FIRST tip read from a stale one.

    Exactly what a per-call-failover client produces when the two calls land on different
    endpoints, and what a reorg between them looks like from the caller's side.
    """

    def __init__(self, utxos, *, stale_tip: int, real_tip: int, stale_reads: int) -> None:
        super().__init__(utxos, tip=stale_tip)
        self._real_tip = real_tip
        self._stale_reads = stale_reads

    async def get_tip_height(self):
        self.calls.append("get_tip_height")
        if self._stale_reads > 0:
            self._stale_reads -= 1
            return self._tip
        return self._real_tip


@pytest.mark.asyncio
async def test_a_lagging_first_tip_read_is_reconciled_not_refused() -> None:
    """The common case: one stale endpoint, then a caught-up one. Depth is REAL, not lost."""
    sh = sr.electrumx_script_hash(COV_SPK)
    client = _LaggingTipClient(
        {sh: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=110)]},
        stale_tip=105,
        real_tip=112,
        stale_reads=1,
    )
    state = await sr.read_covenant_chain_state(client, COV_SPK)
    assert state.depth_unresolved is False
    assert state.tip_height == 112
    assert state.confirmations == 3  # 112 - 110 + 1
    # It cost exactly one extra read, and only because the first one disagreed.
    assert client.calls.count("get_tip_height") == 2


@pytest.mark.asyncio
async def test_a_consistent_first_read_costs_no_extra_round_trip() -> None:
    """The re-read is a repair path, not a tax on every call."""
    sh = sr.electrumx_script_hash(COV_SPK)
    client = _NoBroadcastClient({sh: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=100)]}, tip=105)
    await sr.read_covenant_chain_state(client, COV_SPK)
    assert client.calls.count("get_tip_height") == 1


@pytest.mark.asyncio
async def test_an_unresolved_depth_is_refused_but_the_operator_can_still_override(swap_setup) -> None:
    """The regression, end to end.

    At v0.15.0 this shape produced ``confirmations == 0``, which ``_assert_covenant_confirmed``
    refused and ``--allow-unconfirmed`` could override. The constructor guard moved the
    refusal EARLIER than the override — so the cold builders became unreachable during a CSV
    race on a chain with no RBF and no CPFP. The override is reachable again.
    """
    cov, _t, _m, fee_key = swap_setup
    sh = sr.electrumx_script_hash(COV_SPK)
    client = _LaggingTipClient(
        {sh: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=110)]},
        stale_tip=105,
        real_tip=105,
        stale_reads=99,
    )
    chain = await sr.read_covenant_chain_state(client, COV_SPK)
    assert chain.depth_unresolved is True

    with pytest.raises(ValidationError, match="depth could not be established"):
        sr.build_cold_claim(covenant=cov, chain=chain, preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(9_000_000))

    spend = sr.build_cold_claim(
        covenant=cov,
        chain=chain,
        preimage=P,
        fee_wif=fee_key.wif(),
        fee_utxo=_utxo(9_000_000),
        allow_unconfirmed=True,
    )
    assert bytes.fromhex(spend.raw_hex)  # a real, decodable transaction


def test_an_unresolved_depth_fees_as_if_the_deadline_were_imminent(swap_setup) -> None:
    """The direction of the guess matters more than that a guess is made.

    Reporting the unknown depth as 0 would put ``refund_csv - 0`` blocks on the clock — the
    FULL CSV window, more headroom than any real state has — and hand the operator a lower
    urgency multiplier precisely when the truth is unknown. So the deadline is taken as
    already here: maximum premium, which costs fee and never time.
    """
    cov, _t, _m, fee_key = swap_setup
    unresolved = sr.CovenantChainState(
        outpoint="ab" * 32 + ":0",
        carrier_value=100_000,
        funding_height=110,
        tip_height=105,
        confirmations=0,
        depth_unresolved=True,
    )
    spend = sr.build_cold_claim(
        covenant=cov,
        chain=unresolved,
        preimage=P,
        fee_wif=fee_key.wif(),
        fee_utxo=_utxo(9_000_000),
        allow_unconfirmed=True,
    )
    assert spend.blocks_to_deadline == 0
    assert spend.urgency_multiplier == DeadlineFeePolicy().max_urgency_multiplier
    # And the payload says the depth was never measured, rather than reporting the 0 as a fact.
    assert spend.depth_unresolved is True
    assert spend.to_dict()["depth_unresolved"] is True
    assert spend.csv_mature is False
    # A 0-conf mempool covenant, by contrast, really does have the whole window left.
    mempool = sr.build_cold_claim(
        covenant=cov,
        chain=_chain(0),
        preimage=P,
        fee_wif=fee_key.wif(),
        fee_utxo=_utxo(9_000_000),
        allow_unconfirmed=True,
    )
    assert mempool.blocks_to_deadline == cov.refund_csv
    assert spend.target_photons > mempool.target_photons


def test_an_unresolved_depth_can_never_be_used_to_claim_csv_maturity(swap_setup) -> None:
    """Fail-closed on the refund side: maturity is the one thing an unmeasured depth cannot show."""
    cov, _t, _m, fee_key = swap_setup
    unresolved = sr.CovenantChainState(
        outpoint="ab" * 32 + ":0",
        carrier_value=100_000,
        # A funding height that, taken against a REAL tip, would be far past maturity.
        funding_height=500,
        tip_height=105,
        confirmations=0,
        depth_unresolved=True,
    )
    with pytest.raises(ValidationError, match="maturity cannot be shown"):
        sr.build_cold_refund(
            covenant=cov, chain=unresolved, fee_wif=fee_key.wif(), fee_utxo=_utxo(9_000_000), allow_unconfirmed=True
        )
    prebuilt = sr.build_cold_refund(
        covenant=cov,
        chain=unresolved,
        fee_wif=fee_key.wif(),
        fee_utxo=_utxo(9_000_000),
        allow_unconfirmed=True,
        allow_immature=True,
    )
    assert prebuilt.csv_mature is False


def test_depth_unresolved_is_not_a_flag_an_operator_can_use_to_launder_a_bad_triple() -> None:
    """The escape hatch is narrow: it describes ONE shape and claims no depth."""
    base = {"outpoint": "ab" * 32 + ":0", "carrier_value": 100_000}
    # Not above the tip — nothing to be unresolved about.
    with pytest.raises(ValidationError, match="still put ABOVE the tip"):
        sr.CovenantChainState(**base, funding_height=100, tip_height=105, confirmations=0, depth_unresolved=True)
    # No funding height at all — that is the mempool shape, not this one.
    with pytest.raises(ValidationError, match="still put ABOVE the tip"):
        sr.CovenantChainState(**base, funding_height=None, tip_height=105, confirmations=0, depth_unresolved=True)
    # Above the tip AND claiming a depth.
    with pytest.raises(ValidationError, match="not a measured one"):
        sr.CovenantChainState(**base, funding_height=110, tip_height=105, confirmations=6, depth_unresolved=True)


def test_cold_spend_payload_never_carries_the_fee_key(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    spend = sr.build_cold_claim(
        covenant=cov, chain=_chain(5), preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000)
    )
    blob = json.dumps(spend.to_dict())
    assert fee_key.wif() not in blob
    assert fee_key.wif() not in repr(spend)


# --------------------------------------------------------------------------- covenant rebuild


def test_rebuilt_covenant_must_match_the_persisted_spk(swap_setup) -> None:
    cov, taker, maker, _fee = swap_setup
    rebuilt = sr.rebuild_covenant(
        asset_variant="rxd",
        taker_pkh=bytes(taker.public_key().hash160()),
        maker_pkh=bytes(maker.public_key().hash160()),
        hashlock=H,
        refund_csv=20,
        amount=100_000,
    )
    sr.assert_covenant_matches(rebuilt, cov.funded_spk.hex())


def test_a_wrong_rebuild_input_fails_loudly_instead_of_spending_the_wrong_covenant(swap_setup) -> None:
    cov, taker, maker, _fee = swap_setup
    wrong = sr.rebuild_covenant(
        asset_variant="rxd",
        taker_pkh=bytes(taker.public_key().hash160()),
        maker_pkh=bytes(maker.public_key().hash160()),
        hashlock=H,
        refund_csv=20,
        amount=999_999,  # wrong covenant amount
    )
    with pytest.raises(ValidationError, match="does not match the one in the recovery file"):
        sr.assert_covenant_matches(wrong, cov.funded_spk.hex())


def test_ft_and_nft_rebuilds_require_the_genesis_ref() -> None:
    with pytest.raises(ValidationError, match="genesis ref"):
        sr.rebuild_covenant(
            asset_variant="nft",
            taker_pkh=b"\x01" * 20,
            maker_pkh=b"\x02" * 20,
            hashlock=H,
            refund_csv=20,
            amount=1000,
        )


def test_unknown_asset_variant_is_refused() -> None:
    with pytest.raises(ValidationError, match="unknown asset variant"):
        sr.rebuild_covenant(
            asset_variant="doge", taker_pkh=b"\x01" * 20, maker_pkh=b"\x02" * 20, hashlock=H, refund_csv=20, amount=1
        )


# --------------------------------------------------------------------------- counter-leg reads


class _Facts:
    def __init__(self, counter_chain: str) -> None:
        self.counter_chain = counter_chain
        self.hashlock_hex = H.hex()


@pytest.mark.asyncio
async def test_counter_leg_reports_not_checked_with_a_reason_when_unconfigured() -> None:
    status = await sr.read_counter_leg(_Facts("btc"), sr.RecoveryExtras(), btc_api_url="https://x")
    assert status.state == "NOT_CHECKED"
    assert "only printed it to the console" in status.reason
    assert status.preimage_available is False

    status = await sr.read_counter_leg(
        _Facts("btc"), sr.RecoveryExtras(btc_funding_outpoint="aa" * 32 + ":1"), btc_api_url=None
    )
    assert status.state == "NOT_CHECKED" and "--btc-api-url" in status.reason

    status = await sr.read_counter_leg(_Facts("eth"), sr.RecoveryExtras(), eth_rpc_url="http://x")
    assert status.state == "NOT_CHECKED" and "eth_swap_two_host" in status.reason

    status = await sr.read_counter_leg(_Facts("eth"), sr.RecoveryExtras(eth_contract_address=CONTRACT))
    assert status.state == "NOT_CHECKED" and "--eth-rpc-url" in status.reason


@pytest.mark.asyncio
async def test_counter_leg_reports_a_malformed_outpoint_as_error_not_a_crash() -> None:
    status = await sr.read_counter_leg(
        _Facts("btc"), sr.RecoveryExtras(btc_funding_outpoint="garbage"), btc_api_url="https://x"
    )
    assert status.state == "ERROR"


@pytest.mark.asyncio
async def test_btc_counter_leg_detects_the_claim_but_withholds_p(monkeypatch) -> None:
    raw = _claim_tx()
    spender = btc_txid_from_raw(raw)
    monkeypatch.setattr(sr, "fetch_btc_claim_bytes", AsyncMock(return_value=(True, spender, raw)), raising=True)
    status = await sr.read_btc_counter_leg(MagicMock(), "https://x", funding_outpoint=OUR_FUNDING, hashlock=H)
    assert status.state == "CLAIMED_PREIMAGE_REVEALED"
    assert status.preimage_available is True
    assert status.claim_txid == spender
    # `status` must never print a secret-shaped string; extracting p is a separate verb.
    assert P.hex() not in json.dumps(status.to_dict())


@pytest.mark.asyncio
async def test_btc_counter_leg_states_for_unspent_refund_and_bad_provenance(monkeypatch) -> None:
    monkeypatch.setattr(sr, "fetch_btc_claim_bytes", AsyncMock(return_value=(False, None, None)))
    unspent = await sr.read_btc_counter_leg(MagicMock(), "https://x", funding_outpoint=OUR_FUNDING, hashlock=H)
    assert unspent.state == "LOCKED"

    refund = _refund_tx()
    monkeypatch.setattr(sr, "fetch_btc_claim_bytes", AsyncMock(return_value=(True, btc_txid_from_raw(refund), refund)))
    spent = await sr.read_btc_counter_leg(MagicMock(), "https://x", funding_outpoint=OUR_FUNDING, hashlock=H)
    assert spent.state == "SPENT_NO_PREIMAGE"

    foreign = _claim_tx(outpoint=FOREIGN_FUNDING)
    monkeypatch.setattr(
        sr, "fetch_btc_claim_bytes", AsyncMock(return_value=(True, btc_txid_from_raw(foreign), foreign))
    )
    bad = await sr.read_btc_counter_leg(MagicMock(), "https://x", funding_outpoint=OUR_FUNDING, hashlock=H)
    assert bad.state == "ERROR"

    monkeypatch.setattr(sr, "fetch_btc_claim_bytes", AsyncMock(return_value=(True, "cc" * 32, None)))
    unfetchable = await sr.read_btc_counter_leg(MagicMock(), "https://x", funding_outpoint=OUR_FUNDING, hashlock=H)
    assert unfetchable.state == "ERROR"


@pytest.mark.asyncio
async def test_eth_counter_leg_states(monkeypatch) -> None:
    monkeypatch.setattr(sr, "fetch_eth_claim_artifacts", AsyncMock(return_value=(None, [])))
    locked = await sr.read_eth_counter_leg(MagicMock(), "http://x", contract_address=CONTRACT, hashlock=H)
    assert locked.state == "LOCKED"

    monkeypatch.setattr(
        sr,
        "fetch_eth_claim_artifacts",
        AsyncMock(return_value=(_eth_tx(calldata=P), [_eth_log(data=P)])),
    )
    claimed = await sr.read_eth_counter_leg(MagicMock(), "http://x", contract_address=CONTRACT, hashlock=H)
    assert claimed.state == "CLAIMED_PREIMAGE_REVEALED"
    assert P.hex() not in json.dumps(claimed.to_dict())

    monkeypatch.setattr(sr, "fetch_eth_claim_artifacts", AsyncMock(return_value=(_eth_tx(calldata=b"\x01\x02"), [])))
    refunded = await sr.read_eth_counter_leg(MagicMock(), "http://x", contract_address=CONTRACT, hashlock=H)
    assert refunded.state == "SPENT_NO_PREIMAGE"

    monkeypatch.setattr(sr, "fetch_eth_claim_artifacts", AsyncMock(return_value=(_eth_tx(to=OTHER_CONTRACT), [])))
    unbound = await sr.read_eth_counter_leg(MagicMock(), "http://x", contract_address=CONTRACT, hashlock=H)
    assert unbound.state == "ERROR"


# --------------------------------------------------------------------------- edge validations


def test_a_json_file_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    p = tmp_path / "list.json"
    p.write_text("[1, 2, 3]")
    with pytest.raises(ValidationError, match="not a JSON object"):
        sr.parse_recovery_extras(p)
    with pytest.raises(ValidationError, match="not a JSON object"):
        sr.covenant_pkhs(p)


def test_covenant_pkhs_reject_wrong_length_hashes(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="--taker-pkh must be 20 bytes"):
        sr.covenant_pkhs(_keys_file(tmp_path), taker_pkh_hex="ab" * 10)
    f = _keys_file(tmp_path, taker_rxd_pkh="ab" * 10)
    with pytest.raises(ValidationError, match="taker_rxd_pkh must be 20 bytes"):
        sr.covenant_pkhs(f)


def test_covenant_pkhs_prefer_a_persisted_pkh_over_the_wif(tmp_path: Path) -> None:
    f = _keys_file(tmp_path, taker_rxd_pkh="ab" * 20)
    taker, _maker = sr.covenant_pkhs(f)
    assert taker == bytes.fromhex("ab" * 20)


def test_unparseable_inputs_are_refused_even_when_the_txid_parsed(monkeypatch) -> None:
    # The two parsers are independent walks; a regression in one must still fail closed.
    def _boom(_raw):
        raise ValidationError("bad inputs")

    monkeypatch.setattr(sr, "btc_input_outpoints_from_raw", _boom)
    with pytest.raises(sr.ProvenanceRefused, match="inputs are unparseable"):
        sr.recover_preimage_from_btc_claim(_claim_tx(), hashlock=H, funding_outpoint=OUR_FUNDING)


def test_eth_claim_tx_must_be_a_json_object() -> None:
    with pytest.raises(sr.ProvenanceRefused, match="not an object"):
        sr.recover_preimage_from_eth_claim(hashlock=H, contract_address=CONTRACT, claim_tx="0xdead")


def test_eth_blob_decoding_tolerates_junk_and_reads_topics() -> None:
    # Unusable JSON-RPC field shapes must be SKIPPED, not crash the scan, and a preimage
    # carried in an indexed topic must still be found.
    tx = {"hash": "0xfeed", "to": CONTRACT, "input": 12345}  # not a string at all
    log = {"address": CONTRACT, "data": "0xnothex", "topics": [P], "transactionHash": "0xfeed"}
    rec = sr.recover_preimage_from_eth_claim(hashlock=H, contract_address=CONTRACT, claim_tx=tx, logs=[log])
    assert rec.preimage_hex == P.hex()


def test_fee_selection_with_no_utxos_at_all() -> None:
    with pytest.raises(ValidationError, match="no unspent outputs"):
        sr.select_fee_utxo([], floor=1, target=1, explicit=None)


def test_ft_and_nft_covenants_rebuild_from_a_genesis_ref() -> None:
    ref = "ab" * 32 + ":0"
    ft = sr.rebuild_covenant(
        asset_variant="ft",
        taker_pkh=b"\x01" * 20,
        maker_pkh=b"\x02" * 20,
        hashlock=H,
        refund_csv=20,
        amount=500,
        genesis_ref=ref,
    )
    assert ft.variant == "ft" and len(ft.genesis_ref) == 36
    nft = sr.rebuild_covenant(
        asset_variant="nft",
        taker_pkh=b"\x01" * 20,
        maker_pkh=b"\x02" * 20,
        hashlock=H,
        refund_csv=20,
        amount=1000,
        genesis_ref=ref,
    )
    assert nft.variant == "nft" and len(nft.genesis_ref) == 36


# --------------------------------------------------------------------------- transports (faked)


class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise OSError(f"HTTP {self.status}")

    async def json(self):
        return self._payload


class _SpyRpcSession:
    """Records every JSON-RPC method posted, so the allowlist can be asserted at runtime."""

    def __init__(self, results: list) -> None:
        self._results = list(results)
        self.methods: list[str] = []

    def post(self, url, json=None, timeout=None):
        self.methods.append(json["method"])
        return _FakeResponse(self._results.pop(0))


@pytest.mark.asyncio
async def test_eth_rpc_read_returns_the_result_for_an_allowlisted_method() -> None:
    session = _SpyRpcSession([{"result": "0x2a"}])
    assert await sr.eth_rpc_read(session, "http://x", "eth_blockNumber", []) == "0x2a"
    assert session.methods == ["eth_blockNumber"]


@pytest.mark.asyncio
async def test_eth_rpc_read_surfaces_an_rpc_error_and_a_malformed_body() -> None:
    with pytest.raises(ValidationError, match="RPC error"):
        await sr.eth_rpc_read(_SpyRpcSession([{"error": {"code": -32000}}]), "http://x", "eth_chainId", [])
    with pytest.raises(ValidationError, match="non-object response"):
        await sr.eth_rpc_read(_SpyRpcSession([["not", "an", "object"]]), "http://x", "eth_chainId", [])


@pytest.mark.asyncio
async def test_fetch_eth_claim_artifacts_only_ever_posts_allowlisted_methods() -> None:
    log = _eth_log(data=P, tx_hash="0xfeed")
    session = _SpyRpcSession([{"result": [log]}, {"result": _eth_tx(calldata=P)}])
    tx, logs = await sr.fetch_eth_claim_artifacts(session, "http://x", contract_address=CONTRACT)
    assert tx is not None and logs == [log]
    assert set(session.methods) <= sr.ETH_READ_ONLY_RPC_METHODS


@pytest.mark.asyncio
async def test_fetch_eth_claim_artifacts_handles_no_logs_and_an_unusable_log() -> None:
    empty = _SpyRpcSession([{"result": []}])
    tx, logs = await sr.fetch_eth_claim_artifacts(empty, "http://x", contract_address=CONTRACT)
    assert tx is None and logs == []

    bad = {"address": CONTRACT, "data": "0x"}  # no transactionHash to follow
    session = _SpyRpcSession([{"result": [bad]}])
    tx, logs = await sr.fetch_eth_claim_artifacts(session, "http://x", contract_address=CONTRACT)
    assert tx is None and logs == [bad]

    session = _SpyRpcSession([{"result": [_eth_log(data=P)]}, {"result": "not-a-tx-object"}])
    tx, _ = await sr.fetch_eth_claim_artifacts(session, "http://x", contract_address=CONTRACT)
    assert tx is None


@pytest.mark.asyncio
async def test_fetch_btc_claim_bytes_reuses_the_watchtower_esplora_gets(monkeypatch) -> None:
    from pyrxd.gravity.watch import adapters

    raw = _claim_tx()
    spender = btc_txid_from_raw(raw)
    monkeypatch.setattr(adapters, "mempool_space_outspend", AsyncMock(return_value=(True, spender)))
    monkeypatch.setattr(adapters, "mempool_space_tx_hex", AsyncMock(return_value=raw))
    assert await sr.fetch_btc_claim_bytes(MagicMock(), "https://x", OUR_FUNDING) == (True, spender, raw)

    monkeypatch.setattr(adapters, "mempool_space_outspend", AsyncMock(return_value=(False, None)))
    assert await sr.fetch_btc_claim_bytes(MagicMock(), "https://x", OUR_FUNDING) == (False, None, None)


@pytest.mark.asyncio
async def test_open_http_session_yields_a_closable_session() -> None:
    session = await sr.open_http_session()
    async with session:
        assert session.closed is False
    assert session.closed is True


@pytest.mark.asyncio
async def test_read_counter_leg_dispatches_to_the_configured_chain(monkeypatch) -> None:
    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

    monkeypatch.setattr(sr, "open_http_session", AsyncMock(return_value=_Session()))
    btc_reader = AsyncMock(return_value=sr.CounterLegStatus(chain="btc", state="LOCKED", reason="ok"))
    eth_reader = AsyncMock(return_value=sr.CounterLegStatus(chain="eth", state="LOCKED", reason="ok"))
    monkeypatch.setattr(sr, "read_btc_counter_leg", btc_reader)
    monkeypatch.setattr(sr, "read_eth_counter_leg", eth_reader)

    got = await sr.read_counter_leg(
        _Facts("btc"), sr.RecoveryExtras(btc_funding_outpoint=f"{OUR_FUNDING.txid}:1"), btc_api_url="https://x"
    )
    assert got.chain == "btc" and btc_reader.await_count == 1

    got = await sr.read_counter_leg(
        _Facts("eth"), sr.RecoveryExtras(eth_contract_address=CONTRACT), eth_rpc_url="http://x"
    )
    assert got.chain == "eth" and eth_reader.await_count == 1


# ------------------- audit B4: an unbounded fee overpay burns the whole input ------------------


def test_fee_selection_refuses_a_mistakenly_huge_utxo() -> None:
    """The covenant permits ONE output, so the whole fee input IS the miner fee.

    An ordinary funded key holding a single 500 RXD UTXO was selected without a ceiling and
    burned 50,000,000,000 photons against a ~2,660,000 target — 18,727x — while the CLI
    printed that it "clears the deadline-aware TARGET". Refuse, and say what to do instead.
    """
    with pytest.raises(ValidationError, match="OVERPAY"):
        sr.select_fee_utxo([_utxo(50_000_000_000)], floor=1_000_000, target=2_660_000, explicit=None)


def test_fee_selection_prefers_an_in_band_input_over_a_huge_one() -> None:
    chosen = sr.select_fee_utxo(
        [_utxo(50_000_000_000, "aa"), _utxo(4_000_000, "bb")],
        floor=1_000_000,
        target=2_660_000,
        explicit=None,
    )
    assert chosen.value == 4_000_000


def test_fee_selection_allows_the_overpay_when_the_operator_asks_for_it() -> None:
    chosen = sr.select_fee_utxo(
        [_utxo(50_000_000_000)], floor=1_000_000, target=2_660_000, explicit=None, allow_overpay=True
    )
    assert chosen.value == 50_000_000_000


def test_explicit_fee_utxo_is_also_ceilinged() -> None:
    """Naming a UTXO by hand is not consent to burn 500 RXD on a 0.0266 RXD fee."""
    with pytest.raises(ValidationError, match="OVERPAY"):
        sr.select_fee_utxo([_utxo(50_000_000_000, "aa")], floor=1_000_000, target=2_660_000, explicit="aa" * 32 + ":0")
    chosen = sr.select_fee_utxo(
        [_utxo(50_000_000_000, "aa")],
        floor=1_000_000,
        target=2_660_000,
        explicit="aa" * 32 + ":0",
        allow_overpay=True,
    )
    assert chosen.value == 50_000_000_000


def test_fee_selection_ceiling_is_relative_to_the_target_not_absolute() -> None:
    """A large fee is fine when the requirement is large — the guard is a MULTIPLE."""
    big_target = 5_000_000_000
    chosen = sr.select_fee_utxo([_utxo(6_000_000_000)], floor=1_000_000, target=big_target, explicit=None)
    assert chosen.value == 6_000_000_000


def test_cold_spend_reports_the_overpay_multiple(swap_setup) -> None:
    """The verdict an operator reads must name the overpay, not only the target."""
    cov, _t, _m, fee_key = swap_setup
    spend = sr.build_cold_claim(
        covenant=cov, chain=_chain(5), preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(50_000_000_000)
    )
    assert spend.is_overpay is True
    assert spend.overpay_multiple > 1000
    assert spend.to_dict()["is_overpay"] is True
    modest = sr.build_cold_claim(
        covenant=cov, chain=_chain(5), preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000)
    )
    assert modest.is_overpay is False


# ------------------- audit B5: build-claim must not build against a 0-conf covenant ------------


def test_cold_claim_refuses_an_unconfirmed_covenant(swap_setup) -> None:
    """ElectrumX ``listunspent`` returns MEMPOOL utxos, so ``read_covenant_chain_state`` can
    report a 0-conf covenant. If that parent is conflicted out the claim dies and its fee
    input squats for the 8h mempool expiry — inside the ``t_rxd`` window. The automated leg
    already enforces this (``radiant_leg._resolve_covenant``); the cold path did not.
    """
    cov, _t, _m, fee_key = swap_setup
    with pytest.raises(ValidationError, match="unconfirmed|0 confirmations"):
        sr.build_cold_claim(covenant=cov, chain=_chain(0), preimage=P, fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000))


def test_cold_claim_can_be_built_against_an_unconfirmed_covenant_when_forced(swap_setup) -> None:
    cov, _t, _m, fee_key = swap_setup
    spend = sr.build_cold_claim(
        covenant=cov,
        chain=_chain(0),
        preimage=P,
        fee_wif=fee_key.wif(),
        fee_utxo=_utxo(4_000_000),
        allow_unconfirmed=True,
    )
    assert spend.csv_confirmations == 0


def test_cold_refund_refuses_an_unconfirmed_covenant_even_with_allow_immature(swap_setup) -> None:
    """``--allow-immature`` is about the CSV, not about the parent's existence on-chain."""
    cov, _t, _m, fee_key = swap_setup
    with pytest.raises(ValidationError, match="unconfirmed|0 confirmations"):
        sr.build_cold_refund(
            covenant=cov, chain=_chain(0), fee_wif=fee_key.wif(), fee_utxo=_utxo(4_000_000), allow_immature=True
        )


# ── the recovery file's own permissions ──────────────────────────────────────
#
# ``--fee-wif-file`` holds ONE key, for fees, and has always gone through
# ``read_secret_file``: symlink refused, fstat on the read fd, owner-only mode,
# ownership, size bound. The recovery file holds ``taker_rxd_wif`` AND
# ``maker_rxd_wif`` — both counterparties' spending authority — and was read with a
# bare ``json.loads(path.read_text())``. The care in this module went entirely into
# never letting a WIF into an error message; nothing looked at the file those keys
# sit in at rest.
#
# The writer (``scripts/_dust_swap_shared.atomic_write_mode_600``) gets this right:
# O_EXCL at 0600. The gate is for every way a correct file stops being one — cp,
# rsync -p from a looser source, an unzip, a restore from backup, an editor that
# writes-new-then-renames at umask.


def _public_only_doc() -> dict:
    """A recovery file with no spending authority in it — the two-host shape."""
    return {
        "hashlock_H": H.hex(),
        "rxd_covenant_spk": "76a914" + "11" * 20 + "88ac",
        "t_rxd_blocks": 20,
        "rxd_network": "bc",
        "taker_rxd_pkh": "ab" * 20,
        "maker_rxd_pkh": "cd" * 20,
    }


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660])
def test_a_group_or_world_readable_file_holding_a_wif_is_refused(tmp_path: Path, mode: int) -> None:
    """The whole point. Any bit outside owner is a refusal when keys are present."""
    p = _keys_file(tmp_path)
    p.chmod(mode)
    with pytest.raises(ValidationError, match="chmod 600"):
        sr.load_recovery_json(p)


def test_the_refusal_names_the_remedy_not_the_key(tmp_path: Path) -> None:
    """A permissions error is useless if it does not say what to run, and dangerous
    if it quotes the document it is complaining about."""
    p = _keys_file(tmp_path)
    p.chmod(0o644)
    with pytest.raises(ValidationError) as exc:
        sr.load_recovery_json(p)
    message = str(exc.value)
    assert "chmod 600" in message
    assert "0o644" in message
    doc = json.loads(p.read_text())
    for key in ("taker_rxd_wif", "maker_rxd_wif"):
        leaked = doc[key][:8] in message
        assert not leaked, f"the mode-refusal message quoted {key}"


def test_a_public_only_file_is_not_refused_for_its_mode(tmp_path: Path) -> None:
    """No false alarms. The two-host harnesses persist only public locators, which is
    why --taker-pkh/--maker-pkh exist; demanding 0600 of a public document would
    reject the exact workflow those flags were added for."""
    p = tmp_path / "public.json"
    p.write_text(json.dumps(_public_only_doc()))
    p.chmod(0o644)
    assert sr.load_recovery_json(p)["t_rxd_blocks"] == 20


def test_an_empty_key_field_does_not_trip_the_gate(tmp_path: Path) -> None:
    """A writer that emits an empty ``taker_rxd_wif`` for the peer's absent key has not
    put a key in the file, and must not be told to chmod because of a marker name."""
    doc = _public_only_doc() | {"taker_rxd_wif": "", "maker_rxd_wif": None}
    p = tmp_path / "empty_keys.json"
    p.write_text(json.dumps(doc))
    p.chmod(0o644)
    assert sr.load_recovery_json(p)["t_rxd_blocks"] == 20


def test_a_correctly_permissioned_key_file_still_loads(tmp_path: Path) -> None:
    """The gate must not break the path the real writer produces."""
    p = _keys_file(tmp_path)
    assert sr.load_recovery_json(p)["rxd_network"] == "bc"


def test_a_symlinked_recovery_file_is_read_and_judged_by_its_TARGET(tmp_path: Path) -> None:
    """A recovery path is operator-chosen, and symlinking one into external storage (a
    removable volume, an encrypted mount) is ordinary — the same call
    ``pyrxd.hd.wallet`` already made for a BIP39 seed, a file of at least equal value.
    Refusing here answered one question two ways.

    It is safe because every verdict comes from ``fstat`` on the fd actually opened, so
    the mode and owner judged are the TARGET's — the file whose permissions matter. The
    next test pins that half: a symlink to a 0644 keyful file is still refused.
    """
    real = _keys_file(tmp_path)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    assert sr.load_recovery_json(link)["rxd_network"] == "bc"


def test_a_symlink_cannot_launder_a_world_readable_key_file(tmp_path: Path) -> None:
    """The refuse direction the symlink relaxation must not cost: the mode gate follows
    the link to the real file, so pointing a link at a 0644 keyful file changes nothing."""
    real = _keys_file(tmp_path)
    real.chmod(0o644)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ValidationError, match="contains a private key"):
        sr.load_recovery_json(link)


def test_a_recovery_file_owned_by_a_peer_uid_is_still_refused(tmp_path: Path, monkeypatch) -> None:
    """Root is not a peer; another unprivileged user is. A peer who owns the file
    chooses what the claim is built from, and nothing downstream re-authenticates a
    plaintext recovery JSON."""
    p = _keys_file(tmp_path)
    real_fstat = os.fstat
    peer_uid = os.geteuid() + 1000

    def fake_fstat(fd):
        st = real_fstat(fd)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, peer_uid, *tuple(st)[5:]))

    monkeypatch.setattr(os, "fstat", fake_fstat)
    with pytest.raises(ValidationError, match="owned by uid"):
        sr.load_recovery_json(p)


def test_a_root_written_recovery_file_is_accepted(tmp_path: Path, monkeypatch) -> None:
    """The measured lockout: the harnesses run their nodes in Docker, so a recovery JSON
    written by a root process onto a bind mount was refused outright, mid-incident, with
    no override. Root can substitute the interpreter and the file's contents regardless
    of what this check says, so refusing bought nothing and cost the recovery."""
    p = _keys_file(tmp_path)
    real_fstat = os.fstat

    def fake_fstat(fd):
        st = real_fstat(fd)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 0, *tuple(st)[5:]))

    monkeypatch.setattr(os, "fstat", fake_fstat)
    assert sr.load_recovery_json(p)["rxd_network"] == "bc"


@pytest.mark.parametrize(
    "doc",
    [
        pytest.param({"parties": {"taker_rxd_wif": "L" + "1" * 51}}, id="nested-one-deep"),
        pytest.param({"a": {"b": {"c": {"maker_rxd_wif": "L" + "1" * 51}}}}, id="nested-four-deep"),
        pytest.param({"roles": [{"private_key": "abc"}]}, id="inside-a-list"),
        pytest.param({"mnemonic": "abandon " * 11 + "about"}, id="mnemonic"),
        pytest.param({"wallet": {"seed_hex": "aa" * 64}}, id="nested-seed"),
        pytest.param({"xprv": "xprv9s21ZrQH143K3"}, id="xprv"),
    ],
)
def test_key_material_is_found_at_any_depth_and_under_every_marker(tmp_path: Path, doc: dict) -> None:
    """The gate asks "does this document hold a key?", and a document holds what it holds
    at ANY depth. It walked only the top level, so ``{"parties": {"taker_rxd_wif": ...}}``
    at 0644 was accepted as a public file; and its marker list omitted ``mnemonic``,
    ``seed`` and ``xprv`` — a mnemonic is every key the wallet will ever derive.
    """
    p = tmp_path / "nested.json"
    p.write_text(json.dumps(_public_only_doc() | doc))
    p.chmod(0o644)
    with pytest.raises(ValidationError, match="contains a private key"):
        sr.load_recovery_json(p)


def test_the_deep_walk_does_not_refuse_a_nested_PUBLIC_document(tmp_path: Path) -> None:
    """The accept direction, and the one that matters: widening the search must not turn
    a two-host harness's public locator file into a false alarm. Nested, and every
    marker-named field either absent or empty."""
    doc = _public_only_doc() | {
        "parties": {"taker_rxd_pkh": "11" * 20, "taker_rxd_wif": "", "maker_rxd_wif": None},
        "locators": [{"btc_funding_outpoint": "cc" * 32 + ":3"}],
    }
    p = tmp_path / "nested_public.json"
    p.write_text(json.dumps(doc))
    p.chmod(0o644)
    assert sr.load_recovery_json(p)["t_rxd_blocks"] == 20


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write a 0444 file, so the unrunnable-remedy case cannot arise")
def test_the_mode_remedy_is_one_the_operator_can_actually_run(tmp_path: Path) -> None:
    """``chmod 600 <path>`` cannot succeed on read-only media or a root-written bind
    mount — the two places this gate most often fires. A remedy that cannot succeed
    reads as the tool being broken, so the message names the one that works."""
    p = _keys_file(tmp_path)
    p.chmod(0o444)
    tmp_path.chmod(0o555)  # no unlink/rename either — the archived-media shape
    try:
        with pytest.raises(ValidationError) as exc:
            sr.load_recovery_json(p)
    finally:
        tmp_path.chmod(0o755)
    message = str(exc.value)
    assert "cannot succeed" in message
    assert "install -m 600" in message


def test_a_recovery_file_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    """A FIFO at the recovery path would otherwise block the read forever."""
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    fifo.chmod(0o600)
    with pytest.raises(ValidationError):
        sr.load_recovery_json(fifo)


def test_an_oversized_recovery_file_is_refused(tmp_path: Path) -> None:
    """Bounded read: a wrong path (a disk image, a log) must not be slurped."""
    from pyrxd.gravity.watch.cli_secrets import MAX_SECRET_FILE_BYTES

    p = tmp_path / "huge.json"
    p.write_text("[" + "0," * MAX_SECRET_FILE_BYTES + "0]")
    p.chmod(0o600)
    with pytest.raises(ValidationError, match="larger than"):
        sr.load_recovery_json(p)


def test_malformed_json_does_not_echo_the_offending_line(tmp_path: Path) -> None:
    """``JSONDecodeError`` renders the line it failed on. In this file that line may
    be the one holding a WIF, so the parse error is re-raised ``from None`` with only
    a line NUMBER."""
    wif = PrivateKey().wif()
    p = tmp_path / "broken.json"
    p.write_text('{"taker_rxd_wif": "' + wif + '" ')
    p.chmod(0o600)
    with pytest.raises(ValidationError) as exc:
        sr.load_recovery_json(p)
    node: BaseException | None = exc.value
    while node is not None:
        for text in (str(node), repr(node), repr(node.args)):
            for i in range(len(wif) - 8 + 1):
                assert wif[i : i + 8] not in text, f"the JSON parse error leaked the WIF at offset {i}"
        node = node.__cause__ or node.__context__


@pytest.mark.parametrize("entry", ["parse_recovery_extras", "covenant_pkhs"])
def test_every_public_reader_goes_through_the_gate(tmp_path: Path, entry: str) -> None:
    """Both public entry points, not just the one that happened to get fixed."""
    p = _keys_file(tmp_path)
    p.chmod(0o644)
    with pytest.raises(ValidationError, match="chmod 600"):
        getattr(sr, entry)(p)


def test_the_swap_status_reader_goes_through_the_gate_too(tmp_path: Path) -> None:
    """``swap_cmds.parse_recovery_file`` reports ``has_keys`` to the operator. Telling
    someone their file contains private keys while reading it out of a 0644 file
    without comment was the wrong half of the job."""
    from pyrxd.cli.swap_cmds import parse_recovery_file

    p = _keys_file(tmp_path)
    p.chmod(0o644)
    with pytest.raises(ValidationError, match="chmod 600"):
        parse_recovery_file(p)


# --------------------------------------------------------------------------- the gate judges VALUES
#
# The mode gate above was only ever as good as its list of field NAMES, and a name list
# recognises the names somebody thought of. Measured against the pre-fix walker with a
# real 52-character WIF from ``PrivateKey(os.urandom(32)).wif()``, every document in
# ``KEYFUL_BY_VALUE`` was judged keyless and accepted at 0644 with the key in it.
# ``key_hex`` was a marker while a bare ``key`` was not, which is the shape of the
# problem rather than an entry to add: the list cannot be finished, so the gate has to
# decode the value.


def _fresh_wif() -> str:
    """A real WIF from real entropy. Never a hand-written key — one weak inline test key
    in this repo was swept on a live chain by a scanning bot."""
    return PrivateKey(os.urandom(32)).wif()


#: 12 BIP-39 words. Not a wallet anyone holds — it is the canonical all-``abandon``
#: vector — but it is a real phrase from the shipped English wordlist, which is what
#: ``pyrxd.security.errors._looks_like_mnemonic`` judges.
_MNEMONIC = "abandon " * 11 + "about"


@pytest.mark.parametrize(
    "make_doc",
    [
        pytest.param(lambda w: {"key": w}, id="bare-key"),
        pytest.param(lambda w: {"signing_key": w}, id="signing_key"),
        pytest.param(lambda w: {"priv": w}, id="priv"),
        pytest.param(lambda w: {"taker": w}, id="role-name-only"),
        pytest.param(lambda w: {"parties": [w, w]}, id="bare-list-no-field-name"),
        pytest.param(lambda w: {"a": {"b": [{"c": w}]}}, id="nested-under-nothing"),
        pytest.param(lambda _w: {"recovery_phrase": _MNEMONIC}, id="mnemonic-unmarked-field"),
        pytest.param(lambda _w: {"backup": ["  ".join(_MNEMONIC.split())]}, id="mnemonic-in-a-list"),
        pytest.param(lambda _w: {"k": "9f" * 32}, id="raw-32-byte-hex-unknown-field"),
    ],
)
def test_a_document_is_keyful_because_of_its_VALUE_not_its_field_name(tmp_path: Path, make_doc) -> None:
    """Every one of these was accepted at 0644 before the gate decoded values."""
    doc = _public_only_doc() | make_doc(_fresh_wif())
    p = tmp_path / "byvalue.json"
    p.write_text(json.dumps(doc))
    p.chmod(0o644)
    with pytest.raises(ValidationError, match="contains a private key"):
        sr.load_recovery_json(p)


def test_an_xprv_is_keyful_under_a_field_name_that_says_nothing(tmp_path: Path) -> None:
    """A BIP-32 extended PRIVATE key is 78 payload bytes with 0x00 at index 45 — the
    byte an xpub uses for its 0x02/0x03 SEC prefix. Decoding that byte is what tells the
    two apart, and it is why this does not depend on the string starting with "xprv"."""
    from pyrxd.base58 import base58check_encode

    xprv = base58check_encode(bytes.fromhex("0488ade4") + b"\x00" * 41 + b"\x00" + os.urandom(32))
    doc = _public_only_doc() | {"backup_blob": xprv}
    p = tmp_path / "xprv.json"
    p.write_text(json.dumps(doc))
    p.chmod(0o644)
    with pytest.raises(ValidationError, match="contains a private key"):
        sr.load_recovery_json(p)


@pytest.mark.parametrize(
    "doc",
    [
        pytest.param({}, id="the-plain-public-file"),
        pytest.param({"preimage_p_hex": "de" * 32}, id="preimage-p-is-public-once-revealed"),
        pytest.param({"btc_claim_xonly_hex": "77" * 32}, id="x-only-pubkey-is-64-hex-and-public"),
        pytest.param({"btc_funding_outpoint": "cc" * 32 + ":3"}, id="outpoint"),
        pytest.param({"claim_txid": "ee" * 32}, id="txid-is-64-hex-and-public"),
        pytest.param({"covenant_spk_hex": "76" * 32}, id="a-64-hex-scriptpubkey"),
        pytest.param({"stage": "lock-claim", "rxd_network": "bc", "note": "handed to the taker"}, id="prose"),
        pytest.param({"parties": [{"taker_rxd_pkh": "11" * 20}, {"maker_rxd_pkh": "22" * 20}]}, id="nested-pkhs"),
    ],
)
def test_a_public_locator_file_is_STILL_readable_at_0644(tmp_path: Path, doc: dict) -> None:
    """The accept direction, and the one that pays for the refusals above.

    The two-host harnesses persist only public locators and pkhs — that workflow is why
    ``--taker-pkh`` / ``--maker-pkh`` exist, and refusing it would be a guard that
    refuses valid work. Note ``hashlock_H`` is 64 hex characters and is REQUIRED in
    every recovery file, so a blanket "64 hex means key" rule would have made every
    recovery file keyful; the public-field allowlist is what keeps that from happening,
    and this case is what would catch it if the allowlist lost an entry.
    """
    p = tmp_path / "public.json"
    p.write_text(json.dumps(_public_only_doc() | doc))
    p.chmod(0o644)
    assert sr.load_recovery_json(p)["t_rxd_blocks"] == 20


def test_a_deeply_nested_file_does_not_raise_RecursionError(tmp_path: Path) -> None:
    """A ~1 KB file of ~600 nested lists — well inside the 64 KB read bound — made the
    recursive walker raise an uncaught ``RecursionError``, surfaced by the CLI as
    "unexpected failure (RecursionError)", while ``json.loads`` parsed the same file
    without complaint. Fails closed, so it was availability only; it is still the tool
    breaking on a file it is supposed to judge.
    """
    doc = _public_only_doc() | {"deep": json.loads("[" * 600 + "]" * 600)}
    p = tmp_path / "deep.json"
    p.write_text(json.dumps(doc))
    p.chmod(0o644)
    assert sr.load_recovery_json(p)["t_rxd_blocks"] == 20


def test_a_deeply_nested_file_json_loads_ITSELF_cannot_parse_is_a_clean_refusal(tmp_path: Path) -> None:
    """The same defect one layer up, and it survives an iterative walker.

    Measured on CPython 3.12: ``json.loads`` parses ~5,000 nested lists and raises
    ``RecursionError`` at ~16,000 — 32 KB of ``[``, half of ``MAX_SECRET_FILE_BYTES``,
    so the size bound does not exclude it. Uncaught it is the same "unexpected failure"
    the walker used to produce.
    """
    p = tmp_path / "deeper.json"
    p.write_text("[" * 20_000 + "]" * 20_000)
    p.chmod(0o600)
    with pytest.raises(ValidationError, match="nested too deeply"):
        sr.load_recovery_json(p)


def test_the_gate_and_the_status_command_cannot_disagree(tmp_path: Path) -> None:
    """``swap status`` said ``has_keys=False`` about a ``{"mnemonic": …}`` file at 0600
    while the gate refused the identical document at 0644 as "contains a private key" —
    two answers to one question, from a tool an operator is consulting because they are
    not sure what their file holds. ``has_keys`` is now the gate's own predicate.
    """
    from pyrxd.cli.swap_cmds import parse_recovery_file

    doc = _public_only_doc() | {"mnemonic": _MNEMONIC}
    p = tmp_path / "mnemonic.json"
    p.write_text(json.dumps(doc))
    p.chmod(0o600)
    assert parse_recovery_file(p).has_keys is True

    p.chmod(0o644)
    with pytest.raises(ValidationError, match="contains a private key"):
        parse_recovery_file(p)


def test_has_keys_agrees_with_the_gate_on_a_public_file_too(tmp_path: Path) -> None:
    """Agreement in the other direction: a public file is neither refused nor reported
    as holding keys. ``holds_secrets`` still notices the preimage separately."""
    from pyrxd.cli.swap_cmds import parse_recovery_file

    p = tmp_path / "public_status.json"
    p.write_text(json.dumps(_public_only_doc() | {"preimage_p_hex": "de" * 32}))
    p.chmod(0o644)
    facts = parse_recovery_file(p)
    assert facts.has_keys is False
    assert facts.has_preimage is True
