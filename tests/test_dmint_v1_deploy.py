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
        TransactionInput(source_txid=src_txid, source_output_index=src_idx)
        for src_txid, src_idx in (inputs or [])
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
            await find_dmint_contract_utxos(
                client, token_ref=_TOKEN_REF, min_confirmations=-1
            )

    @pytest.mark.asyncio
    async def test_num_contracts_out_of_range(self):
        bad_state = DmintV1ContractInitialState(
            num_contracts=0, reward_sats=1, max_height=1, target=1
        )
        client = _MockElectrumXClient()
        with pytest.raises(ValidationError, match="num_contracts"):
            await find_dmint_contract_utxos(
                client, token_ref=_TOKEN_REF, initial_state=bad_state
            )


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
        client = _MockElectrumXClient(
            utxos_by_scripthash=utxos, tx_bytes_by_txid=tx_bytes
        )
        result = await find_dmint_contract_utxos(
            client, token_ref=_TOKEN_REF, initial_state=state
        )
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
        client = _MockElectrumXClient(
            utxos_by_scripthash=utxos, tx_bytes_by_txid=tx_bytes
        )
        # Default min_confirmations=1: unconfirmed is skipped.
        result = await find_dmint_contract_utxos(
            client, token_ref=_TOKEN_REF, initial_state=state
        )
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
        result = await find_dmint_contract_utxos(
            client, token_ref=_TOKEN_REF, initial_state=state
        )
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
        client = _MockElectrumXClient(
            utxos_by_scripthash=utxos, tx_bytes_by_txid=tx_bytes
        )
        result = await find_dmint_contract_utxos(
            client, token_ref=_TOKEN_REF, initial_state=state, limit=2
        )
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
        commit_txid_real, commit_raw = _wrap_in_tx_with_outputs(
            [(commit_vout0_script, 1)]
        )
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
        commit_txid_real, commit_raw = _wrap_in_tx_with_outputs(
            [(commit_vout0_script, 1)]
        )
        token_ref = GlyphRef(txid=Txid(commit_txid_real), vout=0)
        commit_sh = _scripthash_hex(commit_vout0_script)
        client = _MockElectrumXClient(
            tx_bytes_by_txid={commit_txid_real: commit_raw},
            history_by_scripthash={
                commit_sh: [{"tx_hash": commit_txid_real, "height": 100}]
            },
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
            _scripthash_hex(contract_script): [
                _make_utxo_record(real_reveal_txid, tx_pos=0)
            ],
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
        commit_txid_real, commit_raw = _wrap_in_tx_with_outputs(
            [(commit_vout0_script, 1)]
        )
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
            _scripthash_hex(good_script): [
                _make_utxo_record(reveal_txid_real, tx_pos=0)
            ],
            # other_script's UTXO would also be unspent, but it shouldn't
            # be returned — the helper filters by token_ref.
            _scripthash_hex(other_script): [
                _make_utxo_record(reveal_txid_real, tx_pos=1)
            ],
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
            await find_dmint_contract_utxos(
                client, token_ref=_TOKEN_REF, initial_state=state
            )

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
            await find_dmint_contract_utxos(
                client, token_ref=_TOKEN_REF, initial_state=state
            )

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
        result = await find_dmint_contract_utxos(
            client, token_ref=_TOKEN_REF, initial_state=state
        )
        assert len(result) == 1
        # The returned DmintContractUtxo's script must round-trip parse to V1.
        parsed = DmintState.from_script(result[0].script)
        assert parsed.is_v1 is True
