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
    p.write_text(json.dumps(doc))
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
    chosen = sr.select_fee_utxo(
        [_utxo(3_000_000, "aa"), _utxo(9_000_000, "bb")], floor=1, target=1, explicit="bb" * 32 + ":0"
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
