"""Tests for M2 V1-deploy chain helper: ``find_dmint_contract_utxos``.

These tests use a hand-rolled ``_MockElectrumXClient`` (mirroring the
M1 mint tests' pattern at ``tests/test_dmint_v1_mint.py:1159``) so the
helper can be driven through every code path without a network.

The fast-path tests build the EXPECTED contract script locally with
the same M1 builder the production code uses, then arrange for the
mock to return that exact script bytes — that is the right level of
mocking, since the helper's job IS to look up scripts by hash.

The walk-from-reveal tests construct a synthetic deploy reveal TX
with N V1-shaped contract outputs and verify enumeration behaviour.

The S2 cross-check tests rig the mock to lie (returning altered
bytes from get_transaction) and verify the helper raises
CovenantError before returning altered scripts.
"""

from __future__ import annotations

from typing import Any

import pytest

from pyrxd.glyph.dmint import (
    DmintAlgo,
    DmintState,
    DmintV1ContractInitialState,
    build_dmint_v1_contract_script,
    find_dmint_contract_utxos,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import CovenantError, ValidationError
from pyrxd.security.types import Txid

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_COMMIT_TXID = "aa" * 32  # display-order hex
_TOKEN_REF = GlyphRef(txid=Txid(_COMMIT_TXID), vout=0)


def _initial_state(num: int = 3) -> DmintV1ContractInitialState:
    """Conservative defaults that fit V1's 3-byte ceilings."""
    return DmintV1ContractInitialState(
        num_contracts=num,
        reward_sats=1_000,
        max_height=100,
        target=0x00FFFFFF_FFFFFFFF,
    )


def _build_contract_script_for_index(i: int, *, num_contracts: int = 3) -> bytes:
    """Reconstruct the expected initial codescript for vout i+1 of the commit."""
    state = _initial_state(num_contracts)
    return build_dmint_v1_contract_script(
        height=0,
        contract_ref=GlyphRef(txid=Txid(_COMMIT_TXID), vout=i + 1),
        token_ref=_TOKEN_REF,
        max_height=state.max_height,
        reward=state.reward_sats,
        target=state.target,
        algo=DmintAlgo.SHA256D,
    )


def _wrap_in_tx_with_outputs(
    scripts_with_values: list[tuple[bytes, int]],
    *,
    inputs: list[tuple[str, int]] | None = None,
) -> tuple[str, bytes]:
    """Build a minimal raw tx with the given outputs and return ``(txid, raw_bytes)``.

    The txid is computed from the actual serialized tx so the mock data
    stays internally consistent with the S2 cross-check (which re-derives
    the txid from get_transaction's bytes).

    :param inputs: Optional list of ``(source_txid, source_output_index)``
        pairs to use as inputs. Default is no inputs (which makes the tx
        unable to "spend" any prevout — only valid for purely synthetic
        UTXO-source tests).
    """
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    tx_inputs = [
        TransactionInput(source_txid=src_txid, source_output_index=src_idx) for src_txid, src_idx in (inputs or [])
    ]
    outputs = [TransactionOutput(Script(s), v) for s, v in scripts_with_values]
    tx = Transaction(tx_inputs=tx_inputs, tx_outputs=outputs)
    raw = bytes(tx.serialize())
    return tx.txid(), raw


def _make_utxo_record(tx_hash: str, tx_pos: int = 0, value: int = 1, height: int = 100):
    from pyrxd.network.electrumx import UtxoRecord

    return UtxoRecord(tx_hash=tx_hash, tx_pos=tx_pos, value=value, height=height)


class _MockElectrumXClient:
    """Stand-in client. Each test sets up the canned responses it needs.

    Maps:
      utxos_by_scripthash:  scripthash hex -> list[UtxoRecord]
      tx_bytes_by_txid:     hex txid -> raw tx bytes
      history_by_scripthash: scripthash hex -> list[{"tx_hash": ..., "height": ...}]
    """

    def __init__(
        self,
        *,
        utxos_by_scripthash: dict[str, list] | None = None,
        tx_bytes_by_txid: dict[str, bytes] | None = None,
        history_by_scripthash: dict[str, list[dict[str, Any]]] | None = None,
    ):
        self.utxos_by_scripthash = utxos_by_scripthash or {}
        self.tx_bytes_by_txid = tx_bytes_by_txid or {}
        self.history_by_scripthash = history_by_scripthash or {}

    async def get_utxos(self, script_hash):
        sh = str(script_hash)
        return list(self.utxos_by_scripthash.get(sh, []))

    async def get_transaction(self, txid):
        s = str(txid)
        if s not in self.tx_bytes_by_txid:
            from pyrxd.security.errors import NetworkError

            raise NetworkError(f"no canned tx for {s}")
        return self.tx_bytes_by_txid[s]

    async def get_history(self, script_hash):
        sh = str(script_hash)
        return list(self.history_by_scripthash.get(sh, []))


def _scripthash_hex(script: bytes) -> str:
    """Mirror the helper's inline scripthash computation."""
    import hashlib

    return hashlib.sha256(script).digest()[::-1].hex()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    @pytest.mark.asyncio
    async def test_token_ref_must_point_at_vout_zero(self):
        bad_ref = GlyphRef(txid=Txid(_COMMIT_TXID), vout=1)
        client = _MockElectrumXClient()
        with pytest.raises(ValidationError, match="vout=0"):
            await find_dmint_contract_utxos(client, token_ref=bad_ref)

    @pytest.mark.asyncio
    async def test_limit_must_be_positive(self):
        client = _MockElectrumXClient()
        with pytest.raises(ValidationError, match="limit"):
            await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, limit=0)

    @pytest.mark.asyncio
    async def test_min_confirmations_must_be_non_negative(self):
        client = _MockElectrumXClient()
        with pytest.raises(ValidationError, match="min_confirmations"):
            await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, min_confirmations=-1)

    @pytest.mark.asyncio
    async def test_num_contracts_out_of_range(self):
        bad_state = DmintV1ContractInitialState(num_contracts=0, reward_sats=1, max_height=1, target=1)
        client = _MockElectrumXClient()
        with pytest.raises(ValidationError, match="num_contracts"):
            await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=bad_state)


# ---------------------------------------------------------------------------
# Shape A: fast path with initial_state
# ---------------------------------------------------------------------------


class TestFastPath:
    @pytest.mark.asyncio
    async def test_returns_all_three_when_all_unspent(self):
        """3 contracts deployed, all unspent → 3 results."""
        state = _initial_state(num=3)
        utxos: dict[str, list] = {}
        tx_bytes: dict[str, bytes] = {}
        for i in range(3):
            s = _build_contract_script_for_index(i)
            sh = _scripthash_hex(s)
            txid, raw = _wrap_in_tx_with_outputs([(b"", 0)] * i + [(s, 1)])
            utxos[sh] = [_make_utxo_record(txid, tx_pos=i)]
            tx_bytes[txid] = raw
        client = _MockElectrumXClient(utxos_by_scripthash=utxos, tx_bytes_by_txid=tx_bytes)
        result = await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=state)
        assert len(result) == 3
        # Each result's state.token_ref must equal our token_ref.
        for r in result:
            assert r.state.token_ref.to_bytes() == _TOKEN_REF.to_bytes()
            assert r.state.is_v1 is True

    @pytest.mark.asyncio
    async def test_skips_unconfirmed_when_min_confirmations_one(self):
        state = _initial_state(num=2)
        s0 = _build_contract_script_for_index(0, num_contracts=2)
        s1 = _build_contract_script_for_index(1, num_contracts=2)
        sh0, sh1 = _scripthash_hex(s0), _scripthash_hex(s1)
        txid0, raw0 = _wrap_in_tx_with_outputs([(s0, 1)])
        txid1, raw1 = _wrap_in_tx_with_outputs([(s1, 1)])
        utxos = {
            sh0: [_make_utxo_record(txid0, height=0)],  # unconfirmed
            sh1: [_make_utxo_record(txid1, height=100)],  # confirmed
        }
        tx_bytes = {txid0: raw0, txid1: raw1}
        client = _MockElectrumXClient(utxos_by_scripthash=utxos, tx_bytes_by_txid=tx_bytes)
        # Default min_confirmations=1: unconfirmed is skipped.
        result = await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=state)
        assert len(result) == 1
        assert result[0].txid == txid1

        # min_confirmations=0: include unconfirmed too.
        result_all = await find_dmint_contract_utxos(
            client, token_ref=_TOKEN_REF, initial_state=state, min_confirmations=0
        )
        assert len(result_all) == 2

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_utxos(self):
        """No UTXOs at any expected scripthash → empty list, no error."""
        state = _initial_state(num=2)
        client = _MockElectrumXClient()  # no canned utxos
        result = await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=state)
        assert result == []

    @pytest.mark.asyncio
    async def test_limit_caps_results(self):
        state = _initial_state(num=3)
        utxos: dict[str, list] = {}
        tx_bytes: dict[str, bytes] = {}
        for i in range(3):
            s = _build_contract_script_for_index(i)
            sh = _scripthash_hex(s)
            txid, raw = _wrap_in_tx_with_outputs([(b"", 0)] * i + [(s, 1)])
            utxos[sh] = [_make_utxo_record(txid, tx_pos=i)]
            tx_bytes[txid] = raw
        client = _MockElectrumXClient(utxos_by_scripthash=utxos, tx_bytes_by_txid=tx_bytes)
        result = await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=state, limit=2)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Shape B: walk-from-reveal fallback
# ---------------------------------------------------------------------------


class TestWalkFromReveal:
    @pytest.mark.asyncio
    async def test_walks_from_commit_to_reveal_and_finds_contracts(self):
        """Synthetic 2-contract deploy: build commit + reveal txs, then verify
        the helper finds both contract UTXOs without being told the params."""
        # Build a "commit" with a synthetic vout 0 (just any non-empty script).
        commit_vout0_script = bytes.fromhex("aa20" + "00" * 32 + "88")  # short, non-V1
        commit_txid_real, commit_raw = _wrap_in_tx_with_outputs([(commit_vout0_script, 1)])
        # Token ref must point at this synthetic commit's vout 0.
        token_ref = GlyphRef(txid=Txid(commit_txid_real), vout=0)
        commit_sh = _scripthash_hex(commit_vout0_script)

        # Build a "reveal" with 2 V1 contract outputs whose contractRef
        # values point back at the synthetic commit's vouts 1+2.
        s0 = build_dmint_v1_contract_script(
            height=0,
            contract_ref=GlyphRef(txid=Txid(commit_txid_real), vout=1),
            token_ref=token_ref,
            max_height=100,
            reward=1_000,
            target=0x00FFFFFF_FFFFFFFF,
        )
        s1 = build_dmint_v1_contract_script(
            height=0,
            contract_ref=GlyphRef(txid=Txid(commit_txid_real), vout=2),
            token_ref=token_ref,
            max_height=100,
            reward=1_000,
            target=0x00FFFFFF_FFFFFFFF,
        )
        # Reveal must spend commit:0 (the FT-commit hashlock) for the
        # helper to identify it as the real deploy reveal.
        reveal_txid_real, reveal_raw = _wrap_in_tx_with_outputs(
            [(s0, 1), (s1, 1)],
            inputs=[(commit_txid_real, 0)],
        )

        utxos = {
            _scripthash_hex(s0): [_make_utxo_record(reveal_txid_real, tx_pos=0)],
            _scripthash_hex(s1): [_make_utxo_record(reveal_txid_real, tx_pos=1)],
        }
        history = {
            commit_sh: [
                {"tx_hash": commit_txid_real, "height": 100},
                {"tx_hash": reveal_txid_real, "height": 100},
            ],
        }
        tx_bytes = {
            commit_txid_real: commit_raw,
            reveal_txid_real: reveal_raw,
        }
        client = _MockElectrumXClient(
            utxos_by_scripthash=utxos,
            tx_bytes_by_txid=tx_bytes,
            history_by_scripthash=history,
        )
        result = await find_dmint_contract_utxos(client, token_ref=token_ref)
        assert len(result) == 2
        assert {r.vout for r in result} == {0, 1}

    @pytest.mark.asyncio
    async def test_returns_empty_when_reveal_not_yet_broadcast(self):
        """Commit exists; history has only the commit; no reveal yet."""
        commit_vout0_script = bytes.fromhex("aa2000" + "00" * 32)
        commit_txid_real, commit_raw = _wrap_in_tx_with_outputs([(commit_vout0_script, 1)])
        token_ref = GlyphRef(txid=Txid(commit_txid_real), vout=0)
        commit_sh = _scripthash_hex(commit_vout0_script)
        client = _MockElectrumXClient(
            tx_bytes_by_txid={commit_txid_real: commit_raw},
            history_by_scripthash={commit_sh: [{"tx_hash": commit_txid_real, "height": 100}]},
        )
        result = await find_dmint_contract_utxos(client, token_ref=token_ref)
        assert result == []

    @pytest.mark.asyncio
    async def test_disambiguates_hashlock_reuse(self):
        """If the FT-commit hashlock script was reused by an earlier failed
        deploy attempt, the scripthash history contains MULTIPLE non-commit
        candidates. The helper must pick the one that actually spends
        commit_txid:0, not the first non-commit entry. Regression test for
        the bug surfaced by the GLYPH live-chain smoke test (where the
        deployer reused the same payload across attempts at h=228398 and
        h=228604)."""
        commit_vout0_script = bytes.fromhex("aa20" + "00" * 32 + "88aa")
        # Distinguish the two attempts by their inputs (otherwise identical
        # output bytes yield identical txids).
        commit_txid_real, commit_raw = _wrap_in_tx_with_outputs(
            [(commit_vout0_script, 1)],
            inputs=[("ff" * 32, 0)],
        )
        token_ref = GlyphRef(txid=Txid(commit_txid_real), vout=0)
        commit_sh = _scripthash_hex(commit_vout0_script)

        # The earlier failed attempt: same vout 0 script bytes, but a
        # different funding input → different txid, same scripthash.
        failed_attempt_txid, failed_raw = _wrap_in_tx_with_outputs(
            [(commit_vout0_script, 1)],
            inputs=[("ee" * 32, 0)],
        )
        assert failed_attempt_txid != commit_txid_real

        # A "spend" of the failed attempt's vout 0 (mimicking d171b184 →
        # 6de766d7 from the chain). This must NOT be mistaken for the
        # deploy reveal.
        unrelated_spend_txid, unrelated_raw = _wrap_in_tx_with_outputs(
            [(b"\x6a", 0)],  # OP_RETURN
            inputs=[(failed_attempt_txid, 0)],
        )

        # The REAL reveal: spends the real commit's vout 0 and creates a
        # V1 contract.
        contract_script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=GlyphRef(txid=Txid(commit_txid_real), vout=1),
            token_ref=token_ref,
            max_height=100,
            reward=1_000,
            target=0x00FFFFFF_FFFFFFFF,
        )
        real_reveal_txid, real_reveal_raw = _wrap_in_tx_with_outputs(
            [(contract_script, 1)],
            inputs=[(commit_txid_real, 0)],
        )

        history = {
            commit_sh: [
                # Order matches the chain — failed attempt first, then
                # commit, then both spends.
                {"tx_hash": failed_attempt_txid, "height": 100},
                {"tx_hash": unrelated_spend_txid, "height": 101},
                {"tx_hash": commit_txid_real, "height": 200},
                {"tx_hash": real_reveal_txid, "height": 200},
            ],
        }
        utxos = {
            _scripthash_hex(contract_script): [_make_utxo_record(real_reveal_txid, tx_pos=0)],
        }
        tx_bytes = {
            failed_attempt_txid: failed_raw,
            unrelated_spend_txid: unrelated_raw,
            commit_txid_real: commit_raw,
            real_reveal_txid: real_reveal_raw,
        }
        client = _MockElectrumXClient(
            utxos_by_scripthash=utxos,
            tx_bytes_by_txid=tx_bytes,
            history_by_scripthash=history,
        )
        result = await find_dmint_contract_utxos(client, token_ref=token_ref)
        # Must find exactly the real contract — the unrelated spend was
        # filtered out by the "spends commit_txid:0" check.
        assert len(result) == 1
        assert result[0].txid == real_reveal_txid

    @pytest.mark.asyncio
    async def test_skips_outputs_with_wrong_token_ref(self):
        """A reveal that contains a V1 contract for a *different* token must
        be filtered out — token_ref mismatch."""
        commit_vout0_script = bytes.fromhex("aa2001" + "00" * 32)
        commit_txid_real, commit_raw = _wrap_in_tx_with_outputs([(commit_vout0_script, 1)])
        token_ref = GlyphRef(txid=Txid(commit_txid_real), vout=0)
        commit_sh = _scripthash_hex(commit_vout0_script)

        # Contract for the right token (token_ref above):
        good_script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=GlyphRef(txid=Txid(commit_txid_real), vout=1),
            token_ref=token_ref,
            max_height=100,
            reward=1_000,
            target=0x00FFFFFF_FFFFFFFF,
        )
        # Contract pointing at a *different* token:
        other_token = GlyphRef(txid=Txid("ee" * 32), vout=0)
        other_script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=GlyphRef(txid=Txid("ee" * 32), vout=1),
            token_ref=other_token,
            max_height=100,
            reward=1_000,
            target=0x00FFFFFF_FFFFFFFF,
        )
        reveal_txid_real, reveal_raw = _wrap_in_tx_with_outputs(
            [(good_script, 1), (other_script, 1)],
            inputs=[(commit_txid_real, 0)],
        )

        utxos = {
            _scripthash_hex(good_script): [_make_utxo_record(reveal_txid_real, tx_pos=0)],
            # other_script's UTXO would also be unspent, but it shouldn't
            # be returned — the helper filters by token_ref.
            _scripthash_hex(other_script): [_make_utxo_record(reveal_txid_real, tx_pos=1)],
        }
        history = {
            commit_sh: [
                {"tx_hash": commit_txid_real, "height": 100},
                {"tx_hash": reveal_txid_real, "height": 100},
            ],
        }
        tx_bytes = {
            commit_txid_real: commit_raw,
            reveal_txid_real: reveal_raw,
        }
        client = _MockElectrumXClient(
            utxos_by_scripthash=utxos,
            tx_bytes_by_txid=tx_bytes,
            history_by_scripthash=history,
        )
        result = await find_dmint_contract_utxos(client, token_ref=token_ref)
        assert len(result) == 1
        assert result[0].state.token_ref.to_bytes() == token_ref.to_bytes()


# ---------------------------------------------------------------------------
# Security S2 cross-check
# ---------------------------------------------------------------------------


class TestSecurityS2:
    """The S2 cross-check defends against an ElectrumX server that lies
    about the script attached to a UTXO. After get_utxos returns a result,
    the helper re-fetches the source transaction and asserts the source
    tx's script matches what the server returned at the UTXO. A mismatch
    must raise CovenantError before the caller can act on bad data."""

    @pytest.mark.asyncio
    async def test_raises_on_script_mismatch(self):
        """Mock returns an unspent UTXO at the right scripthash, but the
        backing transaction at that txid has a *different* script at the
        claimed vout. S2 must raise."""
        state = _initial_state(num=1)
        s = _build_contract_script_for_index(0, num_contracts=1)
        sh = _scripthash_hex(s)
        # Backing tx has a P2PKH at vout 0, NOT our V1 contract script.
        bogus_script = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        bogus_txid, bogus_raw = _wrap_in_tx_with_outputs([(bogus_script, 1)])
        client = _MockElectrumXClient(
            utxos_by_scripthash={sh: [_make_utxo_record(bogus_txid, tx_pos=0)]},
            tx_bytes_by_txid={bogus_txid: bogus_raw},
        )
        with pytest.raises(CovenantError, match="script mismatch"):
            await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=state)

    @pytest.mark.asyncio
    async def test_raises_on_missing_vout(self):
        """Server claims UTXO at vout=5 but the source tx has only 1 output."""
        state = _initial_state(num=1)
        s = _build_contract_script_for_index(0, num_contracts=1)
        sh = _scripthash_hex(s)
        txid, raw = _wrap_in_tx_with_outputs([(s, 1)])
        client = _MockElectrumXClient(
            utxos_by_scripthash={sh: [_make_utxo_record(txid, tx_pos=5)]},
            tx_bytes_by_txid={txid: raw},
        )
        with pytest.raises(CovenantError, match="vout"):
            await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=state)

    @pytest.mark.asyncio
    async def test_passes_when_source_tx_matches(self):
        """Honest server (script at scripthash AND in source tx are equal):
        S2 passes, result returned."""
        state = _initial_state(num=1)
        s = _build_contract_script_for_index(0, num_contracts=1)
        sh = _scripthash_hex(s)
        txid, raw = _wrap_in_tx_with_outputs([(s, 1)])
        client = _MockElectrumXClient(
            utxos_by_scripthash={sh: [_make_utxo_record(txid, tx_pos=0)]},
            tx_bytes_by_txid={txid: raw},
        )
        result = await find_dmint_contract_utxos(client, token_ref=_TOKEN_REF, initial_state=state)
        assert len(result) == 1
        # The returned DmintContractUtxo's script must round-trip parse to V1.
        parsed = DmintState.from_script(result[0].script)
        assert parsed.is_v1 is True


# ---------------------------------------------------------------------------
# Phase 2b.1: V1 deploy library — sibling dataclasses + dispatch
# ---------------------------------------------------------------------------


class TestDmintV1DeployParams:
    """``DmintV1DeployParams`` is the V1 sibling of ``DmintV2DeployParams``.

    Fields are validated at construction via ``__post_init__`` to fail
    fast on invalid deploys before any tx-building work happens."""

    def _meta(self, *, protocol=None):
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

        return GlyphMetadata(
            protocol=protocol or [GlyphProtocol.FT, GlyphProtocol.DMINT],
            name="Test V1",
            ticker="TV1",
        )

    def _hex20(self):
        from pyrxd.security.types import Hex20

        return Hex20(bytes(20))

    def test_construct_valid_v1_params(self):
        from pyrxd.glyph.builder import DmintV1DeployParams

        params = DmintV1DeployParams(
            metadata=self._meta(),
            owner_pkh=self._hex20(),
            num_contracts=32,
            max_height=50_000,
            reward_photons=625_000,
            difficulty=10,
        )
        assert params.num_contracts == 32
        assert params.algo == DmintAlgo.SHA256D

    def test_num_contracts_too_low_rejected(self):
        from pyrxd.glyph.builder import DmintV1DeployParams

        with pytest.raises(ValidationError, match="num_contracts"):
            DmintV1DeployParams(
                metadata=self._meta(),
                owner_pkh=self._hex20(),
                num_contracts=0,
                max_height=10,
                reward_photons=1,
                difficulty=1,
            )

    def test_num_contracts_too_high_rejected(self):
        from pyrxd.glyph.builder import DmintV1DeployParams

        with pytest.raises(ValidationError, match="num_contracts"):
            DmintV1DeployParams(
                metadata=self._meta(),
                owner_pkh=self._hex20(),
                num_contracts=251,
                max_height=10,
                reward_photons=1,
                difficulty=1,
            )

    def test_max_height_3_byte_ceiling(self):
        from pyrxd.glyph.builder import DmintV1DeployParams

        with pytest.raises(ValidationError, match="max_height"):
            DmintV1DeployParams(
                metadata=self._meta(),
                owner_pkh=self._hex20(),
                num_contracts=1,
                max_height=0x1000000,  # 3-byte ceiling + 1
                reward_photons=1,
                difficulty=1,
            )

    def test_reward_photons_3_byte_ceiling(self):
        from pyrxd.glyph.builder import DmintV1DeployParams

        with pytest.raises(ValidationError, match="reward_photons"):
            DmintV1DeployParams(
                metadata=self._meta(),
                owner_pkh=self._hex20(),
                num_contracts=1,
                max_height=1,
                reward_photons=0x1000000,
                difficulty=1,
            )

    def test_non_sha256d_algo_rejected(self):
        from pyrxd.glyph.builder import DmintV1DeployParams
        from pyrxd.glyph.dmint import DmintAlgo as _Algo

        with pytest.raises(ValidationError, match="SHA256d"):
            DmintV1DeployParams(
                metadata=self._meta(),
                owner_pkh=self._hex20(),
                num_contracts=1,
                max_height=1,
                reward_photons=1,
                difficulty=1,
                algo=_Algo.BLAKE3,
            )

    def test_frozen(self):
        """Frozen dataclass — assignment to fields raises."""
        from pyrxd.glyph.builder import DmintV1DeployParams

        params = DmintV1DeployParams(
            metadata=self._meta(),
            owner_pkh=self._hex20(),
            num_contracts=1,
            max_height=1,
            reward_photons=1,
            difficulty=1,
        )
        with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
            params.num_contracts = 99  # type: ignore[misc]


class TestPrepareDmintDeployDispatch:
    """The dispatcher in ``GlyphBuilder.prepare_dmint_deploy`` selects V1 vs
    V2 based on the param type. The right return type comes back without
    the caller needing to pass any version flag."""

    def _v1_params(self):
        from pyrxd.glyph.builder import DmintV1DeployParams
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        return DmintV1DeployParams(
            metadata=GlyphMetadata(
                protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                name="Test V1",
                ticker="TV1",
            ),
            owner_pkh=Hex20(bytes(20)),
            num_contracts=2,
            max_height=100,
            reward_photons=1_000,
            difficulty=10,
        )

    def _v2_params(self):
        from pyrxd.glyph.builder import DmintV2DeployParams
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        return DmintV2DeployParams(
            metadata=GlyphMetadata(
                protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                name="Test V2",
                ticker="TV2",
            ),
            owner_pkh=Hex20(bytes(20)),
            max_height=100,
            reward_photons=1_000,
            difficulty=10,
            initial_pool_photons=100_000,
        )

    def test_v1_params_dispatches_to_v1_result(self):
        from pyrxd.glyph.builder import (
            DmintV1DeployResult,
            DmintV2DeployResult,
            GlyphBuilder,
        )

        result = GlyphBuilder().prepare_dmint_deploy(self._v1_params())
        assert isinstance(result, DmintV1DeployResult)
        assert not isinstance(result, DmintV2DeployResult)
        assert result.num_contracts == 2

    def test_v2_params_dispatches_to_v2_result(self):
        from pyrxd.glyph.builder import (
            DmintV1DeployResult,
            DmintV2DeployResult,
            GlyphBuilder,
        )

        result = GlyphBuilder().prepare_dmint_deploy(self._v2_params(), allow_v2_deploy=True)
        assert isinstance(result, DmintV2DeployResult)
        assert not isinstance(result, DmintV1DeployResult)

    def test_v2_default_refusal_unchanged(self):
        """Footgun guard: V2 deploys still refused by default."""
        from pyrxd.glyph.builder import GlyphBuilder
        from pyrxd.security.errors import DmintError

        with pytest.raises(DmintError, match="allow_v2_deploy"):
            GlyphBuilder().prepare_dmint_deploy(self._v2_params())

    def test_v1_no_allow_v2_deploy_needed(self):
        """V1 deploys do NOT require the V2 opt-in flag — they are the
        production path."""
        from pyrxd.glyph.builder import GlyphBuilder

        # Should succeed without allow_v2_deploy=True.
        result = GlyphBuilder().prepare_dmint_deploy(self._v1_params())
        assert result is not None


class TestDmintV1DeployResult:
    """The V1 result carries commit + placeholder contract scripts and
    builds reveal outputs on demand once the commit txid is known."""

    def _params(self, *, num=2, premine=None, op_return_msg=None):
        from pyrxd.glyph.builder import DmintV1DeployParams
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        return DmintV1DeployParams(
            metadata=GlyphMetadata(
                protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                name="V1",
                ticker="V1T",
            ),
            owner_pkh=Hex20(bytes(20)),
            num_contracts=num,
            max_height=100,
            reward_photons=1_000,
            difficulty=10,
            premine_amount=premine,
            op_return_msg=op_return_msg,
        )

    def test_placeholder_contract_scripts_have_num_contracts_entries(self):
        from pyrxd.glyph.builder import GlyphBuilder

        result = GlyphBuilder().prepare_dmint_deploy(self._params(num=5))
        assert len(result.placeholder_contract_scripts) == 5
        # Each placeholder contract is a full V1 layout (state + 145-byte
        # epilogue). Exact length varies with the push-length encoding of
        # reward/max_height/target — 241 bytes for GLYPH-class params
        # (3-byte pushes), shorter for smaller numbers.
        for s in result.placeholder_contract_scripts:
            assert 200 <= len(s) <= 260

    def test_placeholder_contract_scripts_distinct_per_index(self):
        """Each contract has a unique contractRef = (placeholder_txid, i+1)
        so the placeholder scripts MUST differ from each other (in the
        4-byte vout field of the d8 push)."""
        from pyrxd.glyph.builder import GlyphBuilder

        result = GlyphBuilder().prepare_dmint_deploy(self._params(num=3))
        scripts = result.placeholder_contract_scripts
        # All distinct.
        assert len(set(scripts)) == 3

    def test_build_reveal_outputs_substitutes_real_commit_txid(self):
        """The deferred ``build_reveal_outputs(commit_txid)`` rebuilds
        the contract scripts with the real commit txid in place of the
        placeholder."""
        from pyrxd.glyph.builder import GlyphBuilder
        from pyrxd.glyph.dmint import DmintState

        result = GlyphBuilder().prepare_dmint_deploy(self._params(num=2))
        real_commit_txid = "ab" * 32
        reveal = result.build_reveal_outputs(real_commit_txid)
        assert len(reveal.contract_scripts) == 2

        # Each contract script must round-trip parse to V1 state with
        # the real commit_txid in both contractRef and tokenRef.
        for i, s in enumerate(reveal.contract_scripts):
            state = DmintState.from_script(s)
            assert state.is_v1 is True
            assert state.token_ref.txid == real_commit_txid
            assert state.token_ref.vout == 0
            assert state.contract_ref.txid == real_commit_txid
            assert state.contract_ref.vout == i + 1
            assert state.height == 0
            assert state.max_height == 100
            assert state.reward == 1_000

    def test_build_reveal_outputs_with_premine_rejected(self):
        """Premine is deferred work — must raise NotImplementedError."""
        from pyrxd.glyph.builder import GlyphBuilder

        # premine is rejected at prepare_dmint_deploy time (ValidationError),
        # but if a caller constructs DmintV1DeployResult directly with
        # premine_amount set, build_reveal_outputs must still refuse.
        params = self._params(num=1)
        result = GlyphBuilder().prepare_dmint_deploy(params)
        # Manually patch in a premine to exercise the guard.
        object.__setattr__(result, "premine_amount", 100_000)
        with pytest.raises(NotImplementedError, match="premine"):
            result.build_reveal_outputs("00" * 32)

    def test_op_return_msg_emitted_when_set(self):
        from pyrxd.glyph.builder import GlyphBuilder

        result = GlyphBuilder().prepare_dmint_deploy(self._params(op_return_msg=b"hello"))
        reveal = result.build_reveal_outputs("00" * 32)
        assert reveal.op_return_script is not None
        # OP_RETURN 0x6a + 1-byte push opcode (0x05) + "hello"
        assert reveal.op_return_script == b"\x6a\x05hello"

    def test_op_return_absent_when_none(self):
        from pyrxd.glyph.builder import GlyphBuilder

        result = GlyphBuilder().prepare_dmint_deploy(self._params())
        reveal = result.build_reveal_outputs("00" * 32)
        assert reveal.op_return_script is None

    def test_premine_in_params_rejected_at_prepare_time(self):
        """Setting ``premine_amount`` in params is deferred work — caller
        sees the deferral immediately, not three method calls later."""
        from pyrxd.glyph.builder import GlyphBuilder

        with pytest.raises(ValidationError, match="premine"):
            GlyphBuilder().prepare_dmint_deploy(self._params(premine=1_000))


class TestDeprecationAliases:
    """``DmintFullDeployParams`` and ``DmintDeployResult`` are subclass
    aliases that emit ``DeprecationWarning`` at construction. Verifying
    both the warning AND the inheritance shape so a future bare-alias
    refactor would fail the test."""

    def test_dmint_full_deploy_params_emits_warning(self):
        from pyrxd.glyph.builder import DmintFullDeployParams, DmintV2DeployParams
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        with pytest.warns(DeprecationWarning, match="DmintFullDeployParams"):
            instance = DmintFullDeployParams(
                metadata=GlyphMetadata(
                    protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                ),
                owner_pkh=Hex20(bytes(20)),
                max_height=10,
                reward_photons=1,
                difficulty=1,
                initial_pool_photons=100,
            )
        # Inheritance — isinstance check works either direction
        assert isinstance(instance, DmintV2DeployParams)

    def test_dmint_deploy_result_emits_warning(self):
        from pyrxd.glyph.builder import (
            CommitResult,
            DmintDeployResult,
            DmintV2DeployResult,
        )
        from pyrxd.glyph.dmint import DaaMode, DmintDeployParams
        from pyrxd.glyph.dmint import DmintAlgo as _Algo
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.security.types import Hex20

        commit_result = CommitResult(
            commit_script=b"",
            cbor_bytes=b"",
            payload_hash=b"\x00" * 32,
            estimated_fee=0,
        )
        params = DmintDeployParams(
            contract_ref=GlyphRef(txid="00" * 32, vout=0),
            token_ref=GlyphRef(txid="00" * 32, vout=0),
            max_height=1,
            reward=1,
            difficulty=1,
            algo=_Algo.SHA256D,
            daa_mode=DaaMode.FIXED,
            target_time=60,
            half_life=3600,
        )
        with pytest.warns(DeprecationWarning, match="DmintDeployResult"):
            instance = DmintDeployResult(
                commit_result=commit_result,
                cbor_bytes=b"",
                owner_pkh=Hex20(bytes(20)),
                premine_amount=None,
                deploy_params_template=params,
                placeholder_contract_script=b"",
                initial_pool_photons=100,
            )
        assert isinstance(instance, DmintV2DeployResult)

    def test_subclass_pattern_not_bare_alias(self):
        """``DmintFullDeployParams is DmintV2DeployParams`` would mean a
        bare alias — failing this assertion would mean the
        DeprecationWarning is lost (alias assignments don't run __init__)."""
        from pyrxd.glyph.builder import DmintFullDeployParams, DmintV2DeployParams

        assert DmintFullDeployParams is not DmintV2DeployParams
        assert issubclass(DmintFullDeployParams, DmintV2DeployParams)


class TestV1CborShape:
    """V1 dMint CBOR must satisfy the chain-truth shape from
    ``docs/dmint-research-photonic-deploy.md`` §4: ``p:[1,4]``, no ``v``
    field, all dMint params live in contract scripts (not CBOR)."""

    def test_no_v_field_in_cbor(self):
        """Pin test: V1 CBOR body must NOT include the V2 'v' marker.
        Indexers select V1 vs V2 parser from this field's presence."""
        import cbor2

        from pyrxd.glyph.builder import DmintV1DeployParams, GlyphBuilder
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        params = DmintV1DeployParams(
            metadata=GlyphMetadata(
                protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                name="V1",
                ticker="V1T",
            ),
            owner_pkh=Hex20(bytes(20)),
            num_contracts=1,
            max_height=10,
            reward_photons=1,
            difficulty=1,
        )
        result = GlyphBuilder().prepare_dmint_deploy(params)
        decoded = cbor2.loads(result.cbor_bytes)
        assert "v" not in decoded, f"V1 CBOR must NOT include 'v'; got keys={sorted(decoded)}"
        assert decoded["p"] == [1, 4]

    def test_no_dmint_dict_in_cbor(self):
        """Pin test: V1 CBOR must NOT include a 'dmint' sub-dict — V1
        encodes dMint params in the contract script, not the metadata."""
        import cbor2

        from pyrxd.glyph.builder import DmintV1DeployParams, GlyphBuilder
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        params = DmintV1DeployParams(
            metadata=GlyphMetadata(
                protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                name="V1",
                ticker="V1T",
            ),
            owner_pkh=Hex20(bytes(20)),
            num_contracts=1,
            max_height=10,
            reward_photons=1,
            difficulty=1,
        )
        result = GlyphBuilder().prepare_dmint_deploy(params)
        decoded = cbor2.loads(result.cbor_bytes)
        assert "dmint" not in decoded


class TestV1GoldenVectorGlyphPattern:
    """Byte-equal golden-vector tests against the on-chain GLYPH deploy
    decoded in Phase 2a research. These pin the V1 deploy library to
    the exact bytes the live Radiant ecosystem expects.

    Per ``docs/solutions/logic-errors/dmint-v1-mint-shape-mismatch.md``,
    golden vectors for builders MUST come from real mainnet bytes —
    synthetic round-trip tests are insufficient because they only
    verify self-consistency, not chain-compatibility."""

    # The on-chain values for the GLYPH deploy at h=228604:
    _COMMIT_TXID = "a443d9df469692306f7a2566536b19ed7909d8bf264f5a01f5a9b171c7c3878b"
    _NUM_CONTRACTS = 32
    # NB: chain order is max_height THEN reward (the M1 builder agrees).
    # 32 × 625,000 × 50,000 = 1,000,000,000,000 sats = 10,000 GLYPH.
    _MAX_HEIGHT = 625_000  # first 3-byte push at state offset 79..82
    _REWARD = 50_000  # second 3-byte push at state offset 83..86
    _TARGET = 0x00DA740DA740DA74
    _OWNER_PKH_HEX = "7d6c507735322c6bac9398317a65b4597072f0a6"

    # Vout 0 of the on-chain reveal b965b32d…9dd6 — first of 32
    # contract UTXOs. From Phase 2a research:
    # state[0..4]   = 04 00000000          (height=0)
    # state[5..41]  = d8 <a443d9df:1>      (contractRef[0])
    # state[42..78] = d0 <a443d9df:0>      (tokenRef)
    # state[79..82] = 03 689009            (max_height = 625,000 LE)
    # state[83..86] = 03 50c300            (reward = 50,000 LE)
    # state[87..95] = 08 74da40a70d74da00  (target LE = 0x00da740da740da74)
    _GLYPH_CONTRACT_0_HEX = (
        "0400000000"
        "d8"
        "8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a4"
        "01000000"
        "d0"
        "8b87c3c771b1a9f5015a4f26bfd80979ed196b5366257a6f30929646dfd943a4"
        "00000000"
        "036889090350c3000874da40a70d74da00"
        "bd5175c0c855797ea8597959797ea87e5a7a7eaabc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e9885379cc519d75686d7551"
    )

    def test_v1_contract_script_byte_equals_glyph_vout_0(self):
        """The library's V1 contract script for the GLYPH parameters must
        byte-equal the on-chain script at vout 0 of the deploy reveal.
        This is the strongest possible test: real chain truth as oracle."""
        from pyrxd.glyph.dmint import (
            DmintAlgo as _Algo,
        )
        from pyrxd.glyph.dmint import (
            build_dmint_v1_contract_script,
        )
        from pyrxd.glyph.types import GlyphRef
        from pyrxd.security.types import Txid

        token_ref = GlyphRef(txid=Txid(self._COMMIT_TXID), vout=0)
        contract_ref_0 = GlyphRef(txid=Txid(self._COMMIT_TXID), vout=1)
        script = build_dmint_v1_contract_script(
            height=0,
            contract_ref=contract_ref_0,
            token_ref=token_ref,
            max_height=self._MAX_HEIGHT,
            reward=self._REWARD,
            target=self._TARGET,
            algo=_Algo.SHA256D,
        )
        expected = bytes.fromhex(self._GLYPH_CONTRACT_0_HEX)
        assert script == expected, (
            f"V1 contract script must byte-equal GLYPH reveal vout 0.\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {script.hex()}"
        )

    def test_build_reveal_outputs_produces_glyph_byte_equal(self):
        """End-to-end byte-equality: prepare_dmint_deploy +
        build_reveal_outputs with GLYPH-equivalent params produces a
        reveal vout 0 byte-equal to the on-chain reveal."""
        from pyrxd.glyph.builder import DmintV1DeployParams, GlyphBuilder

        # difficulty maps to target via difficulty_to_target — for the
        # exact on-chain GLYPH target we need to reverse the conversion.
        from pyrxd.glyph.dmint import MAX_SHA256D_TARGET
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
        from pyrxd.security.types import Hex20

        difficulty = MAX_SHA256D_TARGET // self._TARGET

        params = DmintV1DeployParams(
            metadata=GlyphMetadata(
                protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
                name="Glyph Protocol",
                ticker="GLYPH",
                description="The first of its kind",
            ),
            owner_pkh=Hex20(bytes.fromhex(self._OWNER_PKH_HEX)),
            num_contracts=self._NUM_CONTRACTS,
            max_height=self._MAX_HEIGHT,
            reward_photons=self._REWARD,
            difficulty=difficulty,
        )
        result = GlyphBuilder().prepare_dmint_deploy(params)
        reveal = result.build_reveal_outputs(self._COMMIT_TXID)

        expected = bytes.fromhex(self._GLYPH_CONTRACT_0_HEX)
        assert reveal.contract_scripts[0] == expected, (
            "GlyphBuilder.prepare_dmint_deploy → build_reveal_outputs must produce "
            "byte-equal V1 contract output to the on-chain GLYPH deploy reveal at vout 0."
        )
        # All 32 contracts must have the right token_ref and unique contract_ref.
        assert len(reveal.contract_scripts) == 32
        for i, s in enumerate(reveal.contract_scripts):
            from pyrxd.glyph.dmint import DmintState as _State

            state = _State.from_script(s)
            assert state.token_ref.txid == self._COMMIT_TXID
            assert state.contract_ref.vout == i + 1
