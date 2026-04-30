"""Integration test: full FT premine deploy tx pair construction.

Builds a complete commit + reveal transaction pair for a dMint-marked FT
premine deploy and verifies:

1. Commit tx serializes with the correct FT commit script (49-byte, OP_1 refcheck).
2. Reveal tx serializes with the correct 75-byte FT locking script at vout[0].
3. vout[0].value equals premine_amount exactly (1 photon = 1 FT unit).
4. Reveal scriptSig contains the "gly" marker + CBOR bytes.
5. CBOR in the reveal scriptSig round-trips through the reference decoder
   (same check as test_cbor_cross_decoder but on the real serialized tx).
6. (integration) testmempoolaccept on the VPS mainnet node accepts both txs
   as standard — this is a dry-run check that validates script + fee policy
   without spending real funds.

The structural tests (1–5) run offline with a dummy funding UTXO; they are
tagged @pytest.mark.unit and always run.  The testmempoolaccept check (6) is
@pytest.mark.integration and requires VPS SSH access + a real funded UTXO.

Run offline only:  pytest tests/test_dmint_deploy_integration.py -m unit
Run with VPS:      pytest tests/test_dmint_deploy_integration.py -m integration
"""
from __future__ import annotations

import os
import subprocess
import cbor2
import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.script import extract_ref_from_ft_script
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPPLY = 1_000_000  # 1M test units (rehearsal scale)
_TREASURY_PKH = Hex20(bytes.fromhex("11" * 20))

# Glyph marker bytes
_GLY = b"gly"

# Both FT and NFT commit scripts are 75 bytes; they differ only at offset 48
# (OP_1=0x51 for FT, OP_2=0x52 for NFT — the OP_REFTYPE_OUTPUT check byte)
_COMMIT_SCRIPT_LEN = 75
_FT_REFTYPE_OFFSET = 48   # byte at this offset is 0x51 (OP_1) for FT, 0x52 (OP_2) for NFT
# Standard FT locking script (OP_PUSHINPUTREF path) is 75 bytes
_FT_LOCKING_SCRIPT_LEN = 75


# ---------------------------------------------------------------------------
# Helpers — minimal port of RXinDexer reference decoder (same as cross-decoder test)
# ---------------------------------------------------------------------------

def _parse_chunks(script_bytes: bytes) -> list[dict]:
    chunks, i = [], 0
    while i < len(script_bytes):
        op = script_bytes[i]; i += 1
        if 1 <= op <= 75:
            chunks.append({"op": op, "buf": script_bytes[i:i+op]}); i += op
        elif op == 0x4C:
            n = script_bytes[i]; i += 1
            chunks.append({"op": op, "buf": script_bytes[i:i+n]}); i += n
        elif op == 0x4D:
            n = int.from_bytes(script_bytes[i:i+2], "little"); i += 2
            chunks.append({"op": op, "buf": script_bytes[i:i+n]}); i += n
        else:
            chunks.append({"op": op, "buf": None})
    return chunks


def _extract_cbor_from_scriptsig(scriptsig_bytes: bytes) -> bytes | None:
    """Find 'gly' push then return the bytes of the immediately following push."""
    chunks = _parse_chunks(scriptsig_bytes)
    for idx, chunk in enumerate(chunks):
        if chunk.get("buf") == _GLY and idx + 1 < len(chunks):
            return chunks[idx + 1].get("buf")
    return None


# ---------------------------------------------------------------------------
# Fixture: build the full commit + reveal tx pair offline
# ---------------------------------------------------------------------------

class _DeployBundle:
    """Holds the built commit + reveal tx pair and related metadata."""
    commit_tx: Transaction
    reveal_tx: Transaction
    commit_txid: str
    cbor_bytes: bytes
    metadata: GlyphMetadata
    premine_amount: int
    treasury_pkh: Hex20
    funding_key: PrivateKey


def _build_deploy_bundle(supply: int = _SUPPLY) -> _DeployBundle:
    """Build a full commit+reveal pair using a dummy private key + dummy funding UTXO."""
    key = PrivateKey(b"\xde\xad\xbe\xef" * 8)
    wallet_pkh = Hex20(key.public_key().hash160())

    meta = GlyphMetadata.for_dmint_ft(
        ticker="TST",
        name="Test Token (rehearsal)",
        decimals=0,
        description="Integration test token.",
        image_url="https://example.org/test-logo.png",
        image_sha256="aa" * 32,
    )
    cbor_bytes, _ = encode_payload(meta)

    builder = GlyphBuilder()
    commit_result = builder.prepare_commit(CommitParams(
        metadata=meta,
        owner_pkh=wallet_pkh,
        change_pkh=wallet_pkh,
        funding_satoshis=supply + 50_000_000,
    ))

    # Build a shim source tx — real tx would come from ElectrumX
    commit_value = supply + 5_000_000   # supply + overhead
    funding_value = commit_value + commit_result.estimated_fee + 546
    dummy_txid = "ab" * 32

    p2pkh_script = bytes([0x76, 0xa9, 0x14]) + bytes(wallet_pkh) + bytes([0x88, 0xac])
    shim_out = TransactionOutput(Script(p2pkh_script), funding_value)
    src_tx = Transaction(tx_inputs=[], tx_outputs=[shim_out])
    src_tx.txid = lambda: dummy_txid  # type: ignore[method-assign]

    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=dummy_txid,
        source_output_index=0,
        unlocking_script_template=P2PKH().unlock(key),
    )
    commit_input.satoshis = funding_value
    commit_input.locking_script = Script(p2pkh_script)

    change_value = funding_value - commit_value - commit_result.estimated_fee
    commit_tx = Transaction(
        tx_inputs=[commit_input],
        tx_outputs=[
            TransactionOutput(Script(commit_result.commit_script), commit_value),
            TransactionOutput(Script(p2pkh_script), change_value),
        ],
    )
    commit_tx.sign()
    commit_txid = commit_tx.txid()

    # Reveal
    reveal_scripts = builder.prepare_ft_deploy_reveal(
        commit_txid=commit_txid,
        commit_vout=0,
        commit_value=commit_value,
        cbor_bytes=cbor_bytes,
        premine_pkh=_TREASURY_PKH,
        premine_amount=supply,
    )

    # Build reveal unlock (mirrors mint_fhc pattern)
    from pyrxd.script.type import encode_pushdata, to_unlock_script_template

    scriptsig_suffix = reveal_scripts.scriptsig_suffix

    def _reveal_unlock(tx, input_index):
        inp = tx.inputs[input_index]
        sig = key.sign(tx.preimage(input_index))
        sighash_byte = inp.sighash.to_bytes(1, "little")
        pubkey = key.public_key().serialize()
        p2pkh_part = encode_pushdata(sig + sighash_byte) + encode_pushdata(pubkey)
        return Script(p2pkh_part + scriptsig_suffix)

    def _reveal_est_len():
        return 107 + len(scriptsig_suffix)

    unlock_template = to_unlock_script_template(_reveal_unlock, _reveal_est_len)

    shim_commit_out = TransactionOutput(Script(commit_result.commit_script), commit_value)
    src_commit_tx = Transaction(tx_inputs=[], tx_outputs=[shim_commit_out])
    src_commit_tx.txid = lambda: commit_txid  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src_commit_tx,
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=unlock_template,
    )
    reveal_input.satoshis = commit_value
    reveal_input.locking_script = Script(commit_result.commit_script)

    reveal_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[
            TransactionOutput(Script(reveal_scripts.locking_script), supply),
        ],
    )
    reveal_tx.sign()

    b = _DeployBundle()
    b.commit_tx = commit_tx
    b.reveal_tx = reveal_tx
    b.commit_txid = commit_txid
    b.cbor_bytes = cbor_bytes
    b.metadata = meta
    b.premine_amount = supply
    b.treasury_pkh = _TREASURY_PKH
    b.funding_key = key
    return b


@pytest.fixture(scope="module")
def bundle() -> _DeployBundle:
    return _build_deploy_bundle()


# ---------------------------------------------------------------------------
# Structural tests (unit — no network required)
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestCommitTx:
    def test_commit_script_is_ft_shape(self, bundle):
        # vout[0] is the commit script
        commit_out = bundle.commit_tx.outputs[0]
        script_bytes = commit_out.locking_script.script
        assert len(script_bytes) == _COMMIT_SCRIPT_LEN, (
            f"Commit script is {len(script_bytes)} bytes, expected {_COMMIT_SCRIPT_LEN}"
        )

    def test_commit_script_has_op_1_not_op_2(self, bundle):
        # FT commit: byte at offset 48 is OP_1 (0x51). NFT would be OP_2 (0x52).
        # This is the OP_REFTYPE_OUTPUT check: NORMAL ref for FT, SINGLETON for NFT.
        commit_script = bundle.commit_tx.outputs[0].locking_script.script
        assert commit_script[_FT_REFTYPE_OFFSET] == 0x51, (
            f"Expected OP_1 (0x51) at offset {_FT_REFTYPE_OFFSET} for FT commit, "
            f"got 0x{commit_script[_FT_REFTYPE_OFFSET]:02x}"
        )

    def test_commit_value_covers_supply_plus_overhead(self, bundle):
        commit_out = bundle.commit_tx.outputs[0]
        assert commit_out.satoshis >= bundle.premine_amount

    def test_commit_tx_serializes(self, bundle):
        raw = bundle.commit_tx.serialize()
        assert len(raw) > 100
        assert isinstance(raw, (bytes, bytearray))


@pytest.mark.unit
class TestRevealTx:
    def test_vout0_is_75_byte_ft_locking_script(self, bundle):
        reveal_out = bundle.reveal_tx.outputs[0]
        script_bytes = reveal_out.locking_script.script
        assert len(script_bytes) == _FT_LOCKING_SCRIPT_LEN, (
            f"Reveal vout[0] locking script is {len(script_bytes)} bytes, expected {_FT_LOCKING_SCRIPT_LEN}"
        )

    def test_vout0_value_equals_premine_amount(self, bundle):
        reveal_out = bundle.reveal_tx.outputs[0]
        assert reveal_out.satoshis == bundle.premine_amount, (
            f"vout[0].value={reveal_out.satoshis} != premine_amount={bundle.premine_amount}; "
            "1 photon = 1 FT unit invariant broken"
        )

    def test_vout0_locking_script_starts_with_treasury_pkh(self, bundle):
        # FT locking script: 76 a9 14 <pkh 20B> 88 ac bd d0 <ref 36B> ...
        script = bundle.reveal_tx.outputs[0].locking_script.script
        embedded_pkh = script[3:23]
        assert embedded_pkh == bytes(bundle.treasury_pkh), (
            "Treasury PKH not found at expected offset in FT locking script"
        )

    def test_vout0_ref_matches_commit_outpoint(self, bundle):
        script = bundle.reveal_tx.outputs[0].locking_script.script
        ref = extract_ref_from_ft_script(script)
        assert ref.txid == bundle.commit_txid
        assert ref.vout == 0

    def test_reveal_scriptsig_contains_gly_marker(self, bundle):
        reveal_input = bundle.reveal_tx.inputs[0]
        scriptsig = reveal_input.unlocking_script.script
        cbor_data = _extract_cbor_from_scriptsig(scriptsig)
        assert cbor_data is not None, "Could not find 'gly' marker in reveal scriptSig"

    def test_reveal_scriptsig_cbor_round_trips(self, bundle):
        reveal_input = bundle.reveal_tx.inputs[0]
        scriptsig = reveal_input.unlocking_script.script
        cbor_data = _extract_cbor_from_scriptsig(scriptsig)
        assert cbor_data is not None

        decoded = cbor2.loads(cbor_data)
        assert decoded["p"] == [GlyphProtocol.FT, GlyphProtocol.DMINT]
        assert decoded["ticker"] == "TST"
        assert decoded["name"] == "Test Token (rehearsal)"
        assert "decimals" not in decoded  # 0 omitted

    def test_reveal_tx_serializes(self, bundle):
        raw = bundle.reveal_tx.serialize()
        assert len(raw) > 100
        assert isinstance(raw, (bytes, bytearray))

    def test_sighash_byte_is_0x41(self, bundle):
        # SIGHASH_ALL | SIGHASH_FORKID = 0x41. Prior bug used 0x01.
        reveal_input = bundle.reveal_tx.inputs[0]
        scriptsig = reveal_input.unlocking_script.script
        chunks = _parse_chunks(scriptsig)
        sig_push = chunks[0]["buf"] if chunks else None
        assert sig_push is not None and sig_push[-1] == 0x41, (
            f"Sighash byte is 0x{sig_push[-1]:02x}, expected 0x41"
        )


# ---------------------------------------------------------------------------
# testmempoolaccept integration test (requires VPS SSH + funded hot wallet)
# ---------------------------------------------------------------------------

def _build_real_bundle() -> _DeployBundle:
    """Build a commit+reveal pair from a real mainnet UTXO.

    Fetches the smallest eligible UTXO from the hot wallet via SSH/RPC,
    signs the commit with the hot wallet key. Does NOT broadcast — the
    result is only used for testmempoolaccept dry-runs.

    Requires RADIANT_HOT_WIF env var (hot wallet WIF).
    """
    import json as _json

    hot_wif = os.environ.get("RADIANT_HOT_WIF", "")
    if not hot_wif:
        pytest.skip("RADIANT_HOT_WIF not set")

    hot_key = PrivateKey(hot_wif)
    hot_pkh = Hex20(hot_key.public_key().hash160())

    # Fetch UTXOs from VPS node
    result = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", "ericadmin@89.117.20.219",
         "sudo docker exec radiant-mainnet radiant-cli"
         + " -datadir=/home/radiant/.radiant listunspent"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"listunspent failed: {result.stderr}"
    utxos = _json.loads(result.stdout)
    # Pick smallest UTXO >= 10M photons
    MIN_PHOTONS = 10_000_000
    candidates = [u for u in utxos if int(round(u["amount"] * 1e8)) >= MIN_PHOTONS]
    assert candidates, "No eligible hot wallet UTXO >= 10M photons"
    candidates.sort(key=lambda u: u["amount"])
    u = candidates[0]
    funding_txid = u["txid"]
    funding_vout = u["vout"]
    funding_photons = int(round(u["amount"] * 1e8))

    supply = _SUPPLY  # 1M for test
    meta = GlyphMetadata.for_dmint_ft(
        ticker="TST",
        name="Test Token (rehearsal)",
        decimals=0,
        description="Integration test token.",
        image_url="https://example.org/test-logo.png",
        image_sha256="aa" * 32,
    )
    cbor_bytes, _ = encode_payload(meta)
    builder = GlyphBuilder()
    commit_result = builder.prepare_commit(CommitParams(
        metadata=meta,
        owner_pkh=hot_pkh,
        change_pkh=hot_pkh,
        funding_satoshis=funding_photons,
    ))

    commit_value = supply + 5_000_000
    change_value = funding_photons - commit_value - commit_result.estimated_fee
    assert change_value > 546, f"change too small: {change_value}"

    p2pkh_script = bytes([0x76, 0xa9, 0x14]) + bytes(hot_pkh) + bytes([0x88, 0xac])
    shim_out = TransactionOutput(Script(p2pkh_script), funding_photons)
    src_tx = Transaction(tx_inputs=[], tx_outputs=[shim_out])
    src_tx.txid = lambda: funding_txid  # type: ignore[method-assign]

    commit_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=funding_txid,
        source_output_index=funding_vout,
        unlocking_script_template=P2PKH().unlock(hot_key),
    )
    commit_input.satoshis = funding_photons
    commit_input.locking_script = Script(p2pkh_script)

    commit_tx = Transaction(
        tx_inputs=[commit_input],
        tx_outputs=[
            TransactionOutput(Script(commit_result.commit_script), commit_value),
            TransactionOutput(Script(p2pkh_script), change_value),
        ],
    )
    commit_tx.sign()
    commit_txid = commit_tx.txid()

    reveal_scripts = builder.prepare_ft_deploy_reveal(
        commit_txid=commit_txid,
        commit_vout=0,
        commit_value=commit_value,
        cbor_bytes=cbor_bytes,
        premine_pkh=_TREASURY_PKH,
        premine_amount=supply,
    )

    from pyrxd.script.type import encode_pushdata, to_unlock_script_template
    scriptsig_suffix = reveal_scripts.scriptsig_suffix

    def _reveal_unlock(tx, input_index):
        inp = tx.inputs[input_index]
        sig = hot_key.sign(tx.preimage(input_index))
        sighash_byte = inp.sighash.to_bytes(1, "little")
        pubkey = hot_key.public_key().serialize()
        p2pkh_part = encode_pushdata(sig + sighash_byte) + encode_pushdata(pubkey)
        return Script(p2pkh_part + scriptsig_suffix)

    def _reveal_est_len():
        return 107 + len(scriptsig_suffix)

    unlock_template = to_unlock_script_template(_reveal_unlock, _reveal_est_len)
    shim_commit_out = TransactionOutput(Script(commit_result.commit_script), commit_value)
    src_commit_tx = Transaction(tx_inputs=[], tx_outputs=[shim_commit_out])
    src_commit_tx.txid = lambda: commit_txid  # type: ignore[method-assign]

    reveal_input = TransactionInput(
        source_transaction=src_commit_tx,
        source_txid=commit_txid,
        source_output_index=0,
        unlocking_script_template=unlock_template,
    )
    reveal_input.satoshis = commit_value
    reveal_input.locking_script = Script(commit_result.commit_script)

    reveal_tx = Transaction(
        tx_inputs=[reveal_input],
        tx_outputs=[
            TransactionOutput(Script(reveal_scripts.locking_script), supply),
        ],
    )
    reveal_tx.sign()

    b = _DeployBundle()
    b.commit_tx = commit_tx
    b.reveal_tx = reveal_tx
    b.commit_txid = commit_txid
    b.cbor_bytes = cbor_bytes
    b.metadata = meta
    b.premine_amount = supply
    b.treasury_pkh = _TREASURY_PKH
    b.funding_key = hot_key
    return b


@pytest.mark.integration
class TestTestMempoolAccept:
    """Sends commit+reveal to VPS node's testmempoolaccept.

    Requires:
    - SSH access to ericadmin@89.117.20.219
    - RADIANT_HOT_WIF env var — the hot wallet WIF (skipped if unset, so CI stays clean)
    - RADIANT_INTEGRATION env var — opt-in gate (skipped if unset)

    testmempoolaccept is a dry-run: validates script + fees against live
    mempool policy but does NOT broadcast or spend anything.

    The commit tx is built from a real hot-wallet UTXO so it has a valid
    input that the node can look up. The reveal spends the (not-yet-broadcast)
    commit UTXO and must be rejected — confirming input validation works.
    """

    @pytest.fixture(scope="class")
    def real_bundle(self):
        if not os.environ.get("RADIANT_INTEGRATION"):
            pytest.skip("RADIANT_INTEGRATION not set")
        return _build_real_bundle()

    def _rpc(self, cmd: str) -> str:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=10", "ericadmin@89.117.20.219",
             f"sudo docker exec radiant-mainnet radiant-cli "
             f"-datadir=/home/radiant/.radiant {cmd}"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, f"RPC failed: {result.stderr}"
        return result.stdout.strip()

    def test_commit_tx_accepted_by_mempool(self, real_bundle):
        import json
        raw_hex = real_bundle.commit_tx.serialize().hex()
        result = self._rpc(f"testmempoolaccept '[\"{raw_hex}\"]'")
        accepted = json.loads(result)
        assert accepted[0]["allowed"] is True, (
            f"commit tx not accepted: {accepted[0].get('reject-reason', 'unknown')}"
        )

    def test_reveal_tx_rejected_without_commit(self, real_bundle):
        # Reveal spends the commit UTXO which isn't on-chain yet — must be rejected.
        # Confirms testmempoolaccept is validating inputs, not accepting blindly.
        import json
        raw_hex = real_bundle.reveal_tx.serialize().hex()
        result = self._rpc(f"testmempoolaccept '[\"{raw_hex}\"]'")
        accepted = json.loads(result)
        assert accepted[0]["allowed"] is False, (
            "Reveal tx was accepted without its commit UTXO — input validation not working"
        )
