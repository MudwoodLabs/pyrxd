"""Tests for the high-level Glyph mint facade (``pyrxd.glyph.mint``).

The through-line is the hashlock: the commit output can only ever be spent by a reveal
pushing byte-identical CBOR, so the tests that matter are the ones pinning *ordering*
(persist before broadcast) and *integrity* (the stored payload still reproduces the
commit script). The happy path is checked end-to-end against real transaction building
and real signing — only the network and the wallet are stand-ins.

Note on patching: ``pyrxd.glyph`` re-exports lazily through a PEP 562 ``__getattr__``,
which ``mock.patch`` cannot patch through. Everything here patches or drives the
defining module, ``pyrxd.glyph.mint``.
"""

from __future__ import annotations

import json
import os
import stat
import warnings

import pytest

from pyrxd.glyph.mint import (
    DEFAULT_MINT_CONFIRMATIONS,
    NFT_CARRIER_VALUE,
    PENDING_MINT_SCHEMA_VERSION,
    GlyphMinter,
    JsonFilePendingStore,
    MintResult,
    PendingMint,
    PendingMintNotFound,
    PendingStore,
    UnsafeNullPendingStore,
    build_reveal_unlock_template,
)
from pyrxd.glyph.script import build_commit_locking_script, extract_ref_from_nft_script, hash_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import InsufficientFundsError, RxdSdkError, ValidationError

# ---------------------------------------------------------------------------
# Fixtures / doubles
# ---------------------------------------------------------------------------


def _key() -> PrivateKey:
    """A throwaway key from the CSPRNG. Never hand-write key material in tests."""
    return PrivateKey(os.urandom(32))


class FakeClient:
    """Records broadcasts; reports every transaction as confirmed."""

    def __init__(self, *, confirmations: int = 1) -> None:
        self.broadcasts: list[bytes] = []
        self.calls: list[str] = []
        self._confirmations = confirmations

    async def broadcast(self, raw_tx: bytes) -> str:
        from pyrxd.transaction.transaction import Transaction

        self.broadcasts.append(raw_tx)
        self.calls.append("broadcast")
        return Transaction.from_hex(raw_tx.hex()).txid()

    async def get_transaction_verbose(self, txid: str) -> dict:
        return {"confirmations": self._confirmations}


class FakeWallet:
    """The two methods the minter needs, backed by one key and one UTXO."""

    def __init__(self, key: PrivateKey, *, value: int = 50_000_000, tx_pos: int = 0) -> None:
        self.key = key
        self.address = key.public_key().address()
        self.utxo = UtxoRecord(tx_hash="ab" * 32, tx_pos=tx_pos, value=value, height=100)

    async def collect_spendable(self, client: object) -> list:
        return [(self.utxo, self.address, self.key)]

    def privkey_for_address(self, address: str) -> PrivateKey:
        if address != self.address:
            raise ValidationError(f"address {address} is not known to this wallet")
        return self.key


class RecordingStore(PendingStore):
    """In-memory store that logs the call order alongside the client's."""

    def __init__(self, log: list[str] | None = None) -> None:
        self.records: dict[str, PendingMint] = {}
        self.log = log if log is not None else []

    def save(self, pending: PendingMint) -> None:
        self.records[pending.commit_txid] = pending
        self.log.append("save")

    def load(self, commit_txid: str) -> PendingMint:
        try:
            return self.records[commit_txid]
        except KeyError:
            raise PendingMintNotFound(commit_txid) from None

    def delete(self, commit_txid: str) -> None:
        self.records.pop(commit_txid, None)
        self.log.append("delete")

    def list_pending(self) -> list[str]:
        return sorted(self.records)


def _nft_metadata(**kw) -> GlyphMetadata:
    return GlyphMetadata(protocol=[GlyphProtocol.NFT], name="unit-test-nft", **kw)


def _ft_metadata(**kw) -> GlyphMetadata:
    return GlyphMetadata(protocol=[GlyphProtocol.FT], name="unit-test-ft", ticker="UTF", **kw)


def _pending(**overrides) -> PendingMint:
    cbor = b"\xa1\x61p\x81\x02"
    pkh = bytes(range(20))
    fields = {
        "commit_txid": "cd" * 32,
        "commit_vout": 0,
        "commit_value": 6_000_000,
        "commit_script": build_commit_locking_script(hash_payload(cbor), pkh, is_nft=True),
        "cbor_bytes": cbor,
        "owner_pkh": pkh,
        "is_nft": True,
        "carrier_value": NFT_CARRIER_VALUE,
        "fee_rate": 10_000,
        "funding_address": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
    }
    fields.update(overrides)
    return PendingMint(**fields)


# ---------------------------------------------------------------------------
# PendingMint — validation and durable shape
# ---------------------------------------------------------------------------


class TestPendingMint:
    def test_round_trips_through_to_dict(self):
        p = _pending()
        assert PendingMint.from_dict(p.to_dict()) == p

    def test_cbor_is_bytes_in_memory_and_hex_only_on_the_wire(self):
        """House convention: bytes in memory, hex at the wire boundary."""
        p = _pending()
        assert isinstance(p.cbor_bytes, bytes)
        assert isinstance(p.commit_script, bytes)
        assert isinstance(p.owner_pkh, bytes)
        d = p.to_dict()
        assert d["cbor_bytes"] == p.cbor_bytes.hex()
        # ...and the dict must be JSON-serialisable as-is.
        assert json.loads(json.dumps(d))["cbor_bytes"] == p.cbor_bytes.hex()

    def test_to_dict_carries_the_schema_version(self):
        assert _pending().to_dict()["schema_version"] == PENDING_MINT_SCHEMA_VERSION

    @pytest.mark.parametrize("version", [None, 0, 2, "1", PENDING_MINT_SCHEMA_VERSION + 1])
    def test_from_dict_rejects_an_unknown_schema_version(self, version):
        d = _pending().to_dict()
        d["schema_version"] = version
        with pytest.raises(ValidationError, match="schema_version"):
            PendingMint.from_dict(d)

    def test_from_dict_rejects_a_missing_field(self):
        d = _pending().to_dict()
        del d["cbor_bytes"]
        with pytest.raises(ValidationError, match="missing field 'cbor_bytes'"):
            PendingMint.from_dict(d)

    def test_from_dict_rejects_malformed_hex(self):
        d = _pending().to_dict()
        d["cbor_bytes"] = "not-hex"
        with pytest.raises(ValidationError, match="malformed"):
            PendingMint.from_dict(d)

    def test_from_dict_rejects_a_non_dict(self):
        with pytest.raises(ValidationError, match="expects a dict"):
            PendingMint.from_dict(["not", "a", "dict"])

    @pytest.mark.parametrize(
        "override, match",
        [
            ({"commit_txid": "nope"}, "Txid"),
            ({"commit_vout": -1}, "commit_vout"),
            ({"commit_vout": True}, "commit_vout"),
            ({"commit_value": 0}, "commit_value"),
            ({"commit_script": b""}, "commit_script"),
            ({"cbor_bytes": b""}, "cbor_bytes"),
            ({"cbor_bytes": "hex-not-bytes"}, "cbor_bytes"),
            ({"owner_pkh": b"\x00" * 19}, "owner_pkh"),
            ({"is_nft": 1}, "is_nft"),
            ({"carrier_value": 0}, "carrier_value"),
            ({"fee_rate": 0}, "fee_rate"),
            ({"funding_address": ""}, "funding_address"),
        ],
    )
    def test_post_init_validates_every_field(self, override, match):
        with pytest.raises(ValidationError, match=match):
            _pending(**override)

    def test_carrier_value_must_leave_room_for_the_reveal_fee(self):
        with pytest.raises(ValidationError, match="must be below commit_value"):
            _pending(commit_value=1000, carrier_value=1000)

    def test_ref_is_the_commit_outpoint(self):
        """The token's identity is the COMMIT outpoint, not the reveal's."""
        p = _pending()
        assert str(p.ref.txid) == p.commit_txid
        assert p.ref.vout == p.commit_vout


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


class TestJsonFilePendingStore:
    def test_save_load_delete_round_trip(self, tmp_path):
        store = JsonFilePendingStore(tmp_path / "pending")
        p = _pending()
        store.save(p)
        assert store.load(p.commit_txid) == p
        assert store.list_pending() == [p.commit_txid]
        store.delete(p.commit_txid)
        assert store.list_pending() == []

    def test_delete_is_idempotent(self, tmp_path):
        JsonFilePendingStore(tmp_path).delete("ef" * 32)  # must not raise

    def test_load_missing_raises_pending_mint_not_found(self, tmp_path):
        with pytest.raises(PendingMintNotFound):
            JsonFilePendingStore(tmp_path).load("ef" * 32)

    def test_record_is_owner_only_and_directory_is_too(self, tmp_path):
        store = JsonFilePendingStore(tmp_path / "pending")
        p = _pending()
        store.save(p)
        record = store.directory / f"{p.commit_txid}.json"
        assert stat.S_IMODE(record.stat().st_mode) == 0o600
        assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700

    def test_save_leaves_no_temp_file_behind(self, tmp_path):
        """os.replace is atomic; a leftover .tmp would mean the rename never happened."""
        store = JsonFilePendingStore(tmp_path)
        store.save(_pending())
        assert list(tmp_path.glob("*.tmp")) == []

    def test_save_overwrites_in_place(self, tmp_path):
        store = JsonFilePendingStore(tmp_path)
        store.save(_pending())
        store.save(_pending(commit_value=7_000_000))
        assert store.load("cd" * 32).commit_value == 7_000_000
        assert len(store.list_pending()) == 1

    def test_corrupt_json_is_a_validation_error_not_a_crash(self, tmp_path):
        store = JsonFilePendingStore(tmp_path)
        (tmp_path / f"{'ef' * 32}.json").write_text("{not json")
        with pytest.raises(ValidationError, match="not valid JSON"):
            store.load("ef" * 32)

    def test_a_txid_cannot_escape_the_directory(self, tmp_path):
        """Txid() validation is what makes the filename safe to build."""
        store = JsonFilePendingStore(tmp_path)
        with pytest.raises(ValidationError):
            store.load("../../etc/passwd")

    def test_save_rejects_a_non_pending_mint(self, tmp_path):
        with pytest.raises(ValidationError, match="expects a PendingMint"):
            JsonFilePendingStore(tmp_path).save({"commit_txid": "x"})

    def test_save_verifies_the_write_by_reading_it_back(self, tmp_path, monkeypatch):
        """A store that writes something other than what it was given must not
        report success — the caller broadcasts a commit on the strength of it."""
        store = JsonFilePendingStore(tmp_path)
        monkeypatch.setattr(store, "load", lambda txid: _pending(commit_value=999_999))
        with pytest.raises(RxdSdkError, match="did not survive the round-trip"):
            store.save(_pending())

    def test_is_marked_durable(self):
        assert JsonFilePendingStore.durable is True


class TestUnsafeNullPendingStore:
    def test_construction_warns_loudly(self):
        with pytest.warns(UserWarning, match="permanently unspendable"):
            UnsafeNullPendingStore()

    def test_is_not_marked_durable(self):
        assert UnsafeNullPendingStore.durable is False

    def test_discards_and_cannot_resume(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            store = UnsafeNullPendingStore()
        p = _pending()
        store.save(p)
        store.delete(p.commit_txid)
        assert store.list_pending() == []
        with pytest.raises(PendingMintNotFound, match="stores nothing"):
            store.load(p.commit_txid)


def test_pending_store_is_abstract():
    with pytest.raises(TypeError):
        PendingStore()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# GlyphMinter — construction and input guards
# ---------------------------------------------------------------------------


class TestMinterConstruction:
    def test_store_is_required_not_optional(self):
        """The whole point: persistence cannot be defaulted off."""
        with pytest.raises(ValidationError, match="requires a PendingStore"):
            GlyphMinter(FakeClient(), FakeWallet(_key()), None)  # type: ignore[arg-type]

    @pytest.mark.parametrize("bad", [0, -1, True, 1.5])
    def test_rejects_a_bad_fee_rate(self, bad):
        with pytest.raises(ValidationError, match="fee_rate"):
            GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore(), fee_rate=bad)

    @pytest.mark.parametrize("bad", [0, -1, True, "1"])
    def test_rejects_bad_min_confirmations(self, bad):
        with pytest.raises(ValidationError, match="min_confirmations"):
            GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore(), min_confirmations=bad)

    def test_default_confirmations_is_one(self):
        assert DEFAULT_MINT_CONFIRMATIONS == 1

    def test_store_is_exposed_for_resume(self):
        store = RecordingStore()
        assert GlyphMinter(FakeClient(), FakeWallet(_key()), store).store is store


class TestProtocolGuards:
    """Protocol mixes whose reveal is a different shape must be refused BEFORE the
    commit is broadcast — committing to a reveal this module cannot build strands it."""

    @pytest.mark.parametrize(
        "tag, builder_method",
        [
            (GlyphProtocol.MUT, "prepare_mutable_reveal"),
        ],
    )
    async def test_commit_nft_refuses_other_reveal_shapes(self, tag, builder_method):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT, tag], name="x")
        with pytest.raises(ValidationError, match=builder_method):
            await minter.commit_nft(metadata)

    async def test_commit_nft_accepts_a_container(self):
        """A CONTAINER's reveal IS the single-output NFT shape this facade builds.

        Its locking script is the plain 63-byte singleton; container-ness lives in
        the envelope's ``p`` field. Refusing it (as pyrxd did through 0.14.0) was a
        leftover from the removed child-ref prefix, and it meant collections could
        not be minted through the facade or the CLI at all.
        """
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        metadata = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.CONTAINER], name="collection", token_type="container"
        )
        pending = await minter.commit_nft(metadata)
        assert pending.is_nft is True

    async def test_commit_nft_refuses_a_wave_name(self):
        """WAVE is [NFT, MUT, WAVE] — a two-output reveal, like MUT."""
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        metadata = GlyphMetadata(
            protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE],
            name="alice.rxd",
        )
        with pytest.raises(ValidationError, match="cannot mint a (MUT|WAVE) glyph"):
            await minter.commit_nft(metadata)

    async def test_commit_ft_refuses_dmint(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        metadata = GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="x")
        with pytest.raises(ValidationError, match="prepare_dmint_deploy"):
            await minter.commit_ft(metadata, supply=1_000_000)

    async def test_the_mut_refusal_names_the_seed_output_the_caller_must_add(self):
        """A refusal that sends the caller somewhere they will lose funds is not help.

        "Use ``prepare_mutable_reveal`` directly" is true and, on its own, dangerous:
        that reveal takes a SECOND input at ``commit_vout + 1``, so the commit has to
        carry an ordinary output there. A caller who follows the old advice against
        this module's commit shape finds vout 1 is the CHANGE output, which
        ``Transaction.fee()`` removes when it cannot fund it — and the commit is a
        hashlock with no owner-only spend path, so a commit broadcast without its seed
        is unspendable forever.
        """
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT], name="m")
        with pytest.raises(ValidationError) as exc:
            await minter.commit_nft(metadata)
        message = str(exc.value)
        assert "commit_vout + 1" in message, "the refusal must name the seed output"
        assert "hashlock" in message, "the refusal must say what stranding costs"
        assert "nftAuthScript" in message, "the refusal must disclose that pyrxd cannot yet mutate it"

    async def test_the_dmint_refusal_does_not_read_as_a_workaround(self):
        """DMINT is not in the same position as MUT/WAVE and should not sound like it.

        ``prepare_dmint_deploy`` is a complete, consensus-proven path — proven end to
        end against a node in ``tests/test_dmint_premine_regtest_e2e.py``. Calling it
        directly is the supported way to deploy, so the refusal points at a door rather
        than apologising for a wall.
        """
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        metadata = GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="x")
        with pytest.raises(ValidationError) as exc:
            await minter.commit_ft(metadata, supply=1_000_000)
        message = str(exc.value)
        assert "num_contracts" in message, "say what shape the reveal actually is"
        assert "not a workaround" in message

    async def test_commit_nft_requires_the_nft_tag(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="requires GlyphProtocol.NFT"):
            await minter.commit_nft(_ft_metadata())

    async def test_commit_ft_requires_the_ft_tag(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="requires GlyphProtocol.FT"):
            await minter.commit_ft(_nft_metadata(), supply=1_000_000)

    def test_ft_and_nft_together_is_unconstructable(self):
        """Not re-checked in the minter, because GlyphMetadata makes it unreachable."""
        with pytest.raises(ValidationError, match="mutually exclusive"):
            GlyphMetadata(protocol=[GlyphProtocol.NFT, GlyphProtocol.FT], name="x")

    async def test_commit_nft_rejects_a_non_metadata(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="expects a GlyphMetadata"):
            await minter.commit_nft({"protocol": [2]})

    @pytest.mark.parametrize("bad", [545, 0, -1, True, "1000000"])
    async def test_commit_ft_rejects_a_sub_dust_supply(self, bad):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="supply must be an int >= 546"):
            await minter.commit_ft(_ft_metadata(), supply=bad)


# ---------------------------------------------------------------------------
# Commit phase
# ---------------------------------------------------------------------------


class TestCommitPhase:
    async def test_persists_before_broadcasting(self):
        """THE ordering invariant. A commit broadcast before its payload is durable is
        exactly the window that strands the output."""
        log: list[str] = []
        store = RecordingStore(log)
        client = FakeClient()
        client.calls = log  # same list, so the interleaving is visible
        minter = GlyphMinter(client, FakeWallet(_key()), store)

        await minter.commit_nft(_nft_metadata())

        assert log.index("save") < log.index("broadcast")

    async def test_returns_a_pending_that_is_in_the_store(self):
        store = RecordingStore()
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), store)
        pending = await minter.commit_nft(_nft_metadata())
        assert store.load(pending.commit_txid) == pending

    async def test_commit_script_commits_to_the_stored_payload(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        pending = await minter.commit_nft(_nft_metadata())
        # The hashlock is over exactly these bytes.
        assert pending.commit_script[1:34] == b"\x20" + hash_payload(pending.cbor_bytes)

    async def test_ft_commit_records_the_supply_as_the_carrier(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        pending = await minter.commit_ft(_ft_metadata(), supply=2_000_000)
        assert pending.is_nft is False
        assert pending.carrier_value == 2_000_000
        assert pending.commit_value > 2_000_000  # supply + reveal fee

    async def test_nft_commit_uses_a_dust_carrier(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        pending = await minter.commit_nft(_nft_metadata())
        assert pending.is_nft is True
        assert pending.carrier_value == NFT_CARRIER_VALUE

    async def test_owner_defaults_to_the_funding_key(self):
        key = _key()
        minter = GlyphMinter(FakeClient(), FakeWallet(key), RecordingStore())
        pending = await minter.commit_nft(_nft_metadata())
        assert pending.owner_pkh == key.public_key().hash160()

    async def test_owner_can_be_a_third_party(self):
        recipient = _key().public_key().hash160()
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        pending = await minter.commit_nft(_nft_metadata(), owner_pkh=recipient)
        assert pending.owner_pkh == recipient

    async def test_empty_wallet_raises_before_anything_is_broadcast(self):
        class Empty(FakeWallet):
            async def collect_spendable(self, client):
                return []

        client = FakeClient()
        minter = GlyphMinter(client, Empty(_key()), RecordingStore())
        with pytest.raises(InsufficientFundsError, match="no spendable UTXOs"):
            await minter.commit_nft(_nft_metadata())
        assert client.broadcasts == []

    async def test_too_small_a_utxo_raises_before_anything_is_broadcast(self):
        client = FakeClient()
        minter = GlyphMinter(client, FakeWallet(_key(), value=1000), RecordingStore())
        with pytest.raises(InsufficientFundsError, match="no single UTXO is large enough"):
            await minter.commit_nft(_nft_metadata())
        assert client.broadcasts == []

    async def test_a_store_that_drops_the_record_aborts_the_commit(self):
        """The read-back guard lives in the minter, so it covers third-party stores."""

        class Amnesiac(RecordingStore):
            def save(self, pending):
                self.log.append("save")  # accepted, then forgotten

        client = FakeClient()
        minter = GlyphMinter(client, FakeWallet(_key()), Amnesiac())
        with pytest.raises(PendingMintNotFound):
            await minter.commit_nft(_nft_metadata())
        assert client.broadcasts == []

    async def test_a_store_that_mutates_the_record_aborts_the_commit(self):
        class Liar(RecordingStore):
            def load(self, commit_txid):
                return _pending(commit_value=123_456)

        client = FakeClient()
        minter = GlyphMinter(client, FakeWallet(_key()), Liar())
        with pytest.raises(RxdSdkError, match="did not return the pending mint"):
            await minter.commit_nft(_nft_metadata())
        assert client.broadcasts == []

    async def test_null_store_skips_the_readback_instead_of_aborting(self):
        """Opting out has to actually work — but only via the named Unsafe class."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            store = UnsafeNullPendingStore()
        client = FakeClient()
        minter = GlyphMinter(client, FakeWallet(_key()), store)
        pending = await minter.commit_nft(_nft_metadata())
        assert len(client.broadcasts) == 1
        assert store.list_pending() == []
        assert pending.cbor_bytes  # the caller still holds it in memory

    async def test_funding_utxo_at_a_nonzero_vout_is_handled(self):
        """The largest wallet UTXO is often change at vout != 0; the source shim has to
        be padded or fee()/signing index the wrong output."""
        minter = GlyphMinter(FakeClient(), FakeWallet(_key(), tx_pos=3), RecordingStore())
        pending = await minter.commit_nft(_nft_metadata())
        assert pending.commit_value > 0

    async def test_a_disagreeing_broadcast_txid_files_the_payload_under_both(self):
        class Contrarian(FakeClient):
            async def broadcast(self, raw_tx):
                await super().broadcast(raw_tx)
                return "ff" * 32

        store = RecordingStore()
        minter = GlyphMinter(Contrarian(), FakeWallet(_key()), store)
        with pytest.warns(UserWarning, match="stored under BOTH"):
            pending = await minter.commit_nft(_nft_metadata())
        assert set(store.list_pending()) == {pending.commit_txid, "ff" * 32}


# ---------------------------------------------------------------------------
# Reveal phase
# ---------------------------------------------------------------------------


class TestRevealPhase:
    async def test_nft_mint_end_to_end(self):
        """Real builders, real signing — only the network and wallet are doubles."""
        key = _key()
        store = RecordingStore()
        client = FakeClient()
        minter = GlyphMinter(client, FakeWallet(key), store)

        pending = await minter.commit_nft(_nft_metadata())
        result = await minter.reveal_nft(pending)

        assert isinstance(result, MintResult)
        assert result.commit_txid == pending.commit_txid
        assert result.reveal_txid != result.commit_txid
        assert result.reveal_fee > 0
        assert result.carrier_value == NFT_CARRIER_VALUE
        assert len(client.broadcasts) == 2
        # The permanent ref is the COMMIT outpoint, and the reveal's locking script
        # is what carries it on-chain.
        from pyrxd.transaction.transaction import Transaction

        reveal = Transaction.from_hex(client.broadcasts[1].hex())
        assert extract_ref_from_nft_script(reveal.outputs[0].locking_script.serialize()) == result.ref
        assert str(result.ref.txid) == pending.commit_txid

    async def test_reveal_spends_the_commit_output(self):
        key = _key()
        client = FakeClient()
        minter = GlyphMinter(client, FakeWallet(key), RecordingStore())
        pending = await minter.commit_nft(_nft_metadata())
        await minter.reveal_nft(pending)

        from pyrxd.transaction.transaction import Transaction

        reveal = Transaction.from_hex(client.broadcasts[1].hex())
        assert len(reveal.inputs) == 1
        assert reveal.inputs[0].source_txid == pending.commit_txid
        # The scriptSig must carry the exact CBOR the hashlock committed to.
        assert pending.cbor_bytes in reveal.inputs[0].unlocking_script.serialize()

    async def test_ft_deploy_end_to_end(self):
        client = FakeClient()
        minter = GlyphMinter(client, FakeWallet(_key()), RecordingStore())
        pending = await minter.commit_ft(_ft_metadata(), supply=1_500_000)
        result = await minter.reveal_ft(pending)
        assert result.carrier_value == 1_500_000

        from pyrxd.transaction.transaction import Transaction

        reveal = Transaction.from_hex(client.broadcasts[1].hex())
        assert reveal.outputs[0].satoshis == 1_500_000

    async def test_record_is_deleted_only_after_the_reveal_broadcasts(self):
        log: list[str] = []
        store = RecordingStore(log)
        client = FakeClient()
        client.calls = log
        minter = GlyphMinter(client, FakeWallet(_key()), store)

        pending = await minter.commit_nft(_nft_metadata())
        await minter.reveal_nft(pending)

        # broadcast (commit), broadcast (reveal), THEN delete.
        assert log[-1] == "delete"
        assert store.list_pending() == []

    async def test_record_survives_a_failed_reveal_broadcast(self):
        """If the reveal does not relay, the payload must still be recoverable."""

        class Rejecting(FakeClient):
            async def broadcast(self, raw_tx):
                if self.broadcasts:
                    raise RuntimeError("node said no")
                return await super().broadcast(raw_tx)

        store = RecordingStore()
        minter = GlyphMinter(Rejecting(), FakeWallet(_key()), store)
        pending = await minter.commit_nft(_nft_metadata())
        with pytest.raises(RuntimeError, match="node said no"):
            await minter.reveal_nft(pending)
        assert store.load(pending.commit_txid) == pending

    async def test_resume_from_the_store_after_a_crash(self):
        """The whole reason the two phases are separable."""
        key = _key()
        store = RecordingStore()
        client = FakeClient()

        pending = await GlyphMinter(client, FakeWallet(key), store).commit_nft(_nft_metadata())

        # New process, new minter, nothing in memory but the store.
        revived = GlyphMinter(client, FakeWallet(key), store).store.load(pending.commit_txid)
        result = await GlyphMinter(client, FakeWallet(key), store).reveal_nft(revived)
        assert result.ref == pending.ref

    async def test_reveal_nft_refuses_an_ft_pending(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="call reveal_ft"):
            await minter.reveal_nft(_pending(is_nft=False))

    async def test_reveal_ft_refuses_an_nft_pending(self):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="call reveal_nft"):
            await minter.reveal_ft(_pending(is_nft=True))

    @pytest.mark.parametrize("method", ["reveal_nft", "reveal_ft"])
    async def test_reveal_rejects_a_non_pending_mint(self, method):
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="expects a PendingMint"):
            await getattr(minter, method)({"commit_txid": "x"})

    async def test_tampered_cbor_is_refused_before_a_reveal_is_built(self):
        """The integrity check that makes the store trustworthy: if the stored bytes no
        longer reproduce the commit script, the reveal cannot spend it."""
        key = _key()
        client = FakeClient()
        store = RecordingStore()
        minter = GlyphMinter(client, FakeWallet(key), store)
        pending = await minter.commit_nft(_nft_metadata())

        tampered = _pending(
            commit_txid=pending.commit_txid,
            commit_script=pending.commit_script,
            cbor_bytes=pending.cbor_bytes + b"\x00",
            commit_value=pending.commit_value,
            funding_address=pending.funding_address,
        )
        with pytest.raises(ValidationError, match="does not reproduce its commit script"):
            await minter.reveal_nft(tampered)
        assert len(client.broadcasts) == 1  # the reveal was never sent

    async def test_a_flipped_is_nft_flag_is_refused(self):
        """NFT vs FT changes one byte of the commit script (OP_2 vs OP_1)."""
        import dataclasses

        key = _key()
        minter = GlyphMinter(FakeClient(), FakeWallet(key), RecordingStore())
        pending = await minter.commit_ft(_ft_metadata(), supply=1_000_000)
        flipped = dataclasses.replace(pending, is_nft=True, carrier_value=NFT_CARRIER_VALUE)
        with pytest.raises(ValidationError, match="does not reproduce its commit script"):
            await minter.reveal_nft(flipped)

    async def test_the_wrong_wallet_cannot_reveal(self):
        key = _key()
        minter = GlyphMinter(FakeClient(), FakeWallet(key), RecordingStore())
        pending = await minter.commit_nft(_nft_metadata())

        stranger = GlyphMinter(FakeClient(), FakeWallet(_key()), RecordingStore())
        with pytest.raises(ValidationError, match="not known to this wallet"):
            await stranger.reveal_nft(pending)

    async def test_reveal_waits_for_the_configured_depth(self):
        """A commit that never reaches the required depth must not produce a reveal."""
        from pyrxd.security.errors import ConfirmationTimeoutError

        key = _key()
        client = FakeClient(confirmations=1)
        minter = GlyphMinter(
            client,
            FakeWallet(key),
            RecordingStore(),
            min_confirmations=6,
            confirmation_timeout_s=0.001,
        )
        pending = await minter.commit_nft(_nft_metadata())
        with pytest.raises(ConfirmationTimeoutError):
            await minter.reveal_nft(pending)
        assert len(client.broadcasts) == 1


# ---------------------------------------------------------------------------
# Single-call convenience
# ---------------------------------------------------------------------------


class TestConvenienceMethods:
    async def test_mint_nft_composes_both_phases(self):
        client = FakeClient()
        store = RecordingStore()
        result = await GlyphMinter(client, FakeWallet(_key()), store).mint_nft(_nft_metadata())
        assert len(client.broadcasts) == 2
        assert store.list_pending() == []
        assert result.reveal_txid

    async def test_deploy_ft_composes_both_phases(self):
        client = FakeClient()
        result = await GlyphMinter(client, FakeWallet(_key()), RecordingStore()).deploy_ft(
            _ft_metadata(), supply=1_000_000
        )
        assert len(client.broadcasts) == 2
        assert result.carrier_value == 1_000_000

    async def test_convenience_still_persists_before_broadcast(self):
        """The store is a constructor dependency precisely so the one-call path cannot
        skip it."""
        log: list[str] = []
        store = RecordingStore(log)
        client = FakeClient()
        client.calls = log
        await GlyphMinter(client, FakeWallet(_key()), store).mint_nft(_nft_metadata())
        assert log[0] == "save"
        assert log.index("save") < log.index("broadcast")


# ---------------------------------------------------------------------------
# Unlock template
# ---------------------------------------------------------------------------


class TestRevealUnlockTemplate:
    def test_estimated_length_matches_the_fee_module(self):
        """A drifted estimate here makes the reveal fee guard under-estimate and pass,
        which strands the commit."""
        from pyrxd.glyph.fees import REVEAL_SIG_PREFIX_BYTES

        suffix = b"\x00" * 40
        tmpl = build_reveal_unlock_template(_key(), suffix)
        assert tmpl.estimated_unlocking_byte_length() == REVEAL_SIG_PREFIX_BYTES + len(suffix)

    def test_rejects_a_non_bytes_suffix(self):
        with pytest.raises(ValidationError, match="must be bytes"):
            build_reveal_unlock_template(_key(), "not-bytes")

    def test_cli_helper_is_the_same_function(self):
        """The CLI used to carry its own copy; it must not grow one again."""
        from pyrxd.cli.glyph_helpers import _build_glyph_unlock

        key = _key()
        assert (
            _build_glyph_unlock(key, b"\x01\x02").estimated_unlocking_byte_length()
            == build_reveal_unlock_template(key, b"\x01\x02").estimated_unlocking_byte_length()
        )


# ---------------------------------------------------------------------------
# Lazy exports
# ---------------------------------------------------------------------------


def test_public_names_resolve_through_the_lazy_export_dict():
    import pyrxd
    import pyrxd.glyph as glyph_pkg

    for name in (
        "GlyphMinter",
        "JsonFilePendingStore",
        "MintResult",
        "PendingMint",
        "PendingMintNotFound",
        "PendingStore",
        "UnsafeNullPendingStore",
        "build_reveal_unlock_template",
    ):
        assert name in glyph_pkg.__all__
        assert getattr(glyph_pkg, name) is not None
    # __all__ is DERIVED from the dict, never hand-edited.
    assert glyph_pkg.__all__ == sorted(glyph_pkg._LAZY_EXPORTS)
    assert pyrxd.GlyphMinter is glyph_pkg.GlyphMinter
    assert pyrxd.JsonFilePendingStore is glyph_pkg.JsonFilePendingStore


def test_no_export_name_was_silently_overwritten():
    """``_LAZY_EXPORTS`` is a flat dict, so a duplicate public name is a silent
    overwrite — ``TransferResult`` already exists in builder.py, and a second one
    would have replaced it with no error anywhere."""
    import pyrxd.glyph as glyph_pkg

    targets = list(glyph_pkg._LAZY_EXPORTS.values())
    assert len(set(targets)) == len(targets), "two public names resolve to the same target"
    for name, (module, attr) in glyph_pkg._LAZY_EXPORTS.items():
        assert attr == name, f"{name} is re-exported under a different attribute name ({module}.{attr})"


class TestTheRecordOutlivesTheBroadcast:
    """The pending record must survive a reveal that relays but never confirms.

    A mempool accept is not a block. If the reveal is evicted at expiry (~8h) and the
    record was already deleted, the CBOR payload needed to rebuild it is gone — and the
    commit output is a hashlock with no owner-only spend path, so its value is
    unrecoverable. The delete therefore waits for the reveal to confirm.
    """

    @staticmethod
    def _never_confirms():
        """A client that accepts the broadcast and then reports 0 confirmations forever."""

        class _Client(FakeClient):
            def __init__(self) -> None:
                super().__init__(confirmations=0)
                self._commit_txid: str | None = None

            async def get_transaction_verbose(self, txid: str) -> dict:
                # The COMMIT confirms — the reveal cannot even be built otherwise. Every
                # LATER txid is the reveal, and it never confirms: the accepted-then-evicted
                # case this test exists for. Pinning the commit's txid on first sight is
                # deliberate; an earlier version of this fake confirmed the first sighting
                # of *any* txid, which silently confirmed the reveal too and made the test
                # pass against the very bug it was written to catch.
                if self._commit_txid is None:
                    self._commit_txid = txid
                return {"confirmations": 1 if txid == self._commit_txid else 0}

        return _Client()

    async def test_an_unconfirmed_reveal_keeps_the_record(self):
        store = RecordingStore()
        minter = GlyphMinter(
            self._never_confirms(),
            FakeWallet(_key()),
            store,
            confirmation_timeout_s=0.2,
        )
        pending = await minter.commit_nft(_nft_metadata())
        assert store.load(pending.commit_txid) is not None

        with pytest.raises(Exception):
            await minter.reveal_nft(pending)

        # THE assertion. Deleting here would strand the commit permanently.
        assert store.load(pending.commit_txid) is not None, (
            "the pending record was deleted for a reveal that never confirmed — "
            "the commit is a hashlock and its value is now unrecoverable"
        )


class TestRevealRateAndEchoGuards:
    """The reveal-time guards, none of which had a test when they were written.

    An adversarial pass found: the `fee_rate=` override unexercised, the reveal-time
    rate gate unexercised, and `TestTheRecordOutlivesTheBroadcast`'s fixture unable to
    distinguish "waits on the locally derived txid" from "waits on the server's echo",
    because its fake echoed the correct txid either way.
    """

    LIE = "ff" * 32

    @classmethod
    def _lying_client(cls):
        """Echoes a txid it was not handed, and confirms ONLY that one.

        The discrimination matters. An earlier version of this fake confirmed every
        txid, so waiting on the echo and waiting on the locally derived value both
        succeeded and the test proved nothing.

        Here exactly two transactions confirm: the COMMIT, hashed from the bytes this
        fake was handed, and the LIE. The real reveal never does. So code that trusts the
        echo sees "confirmed" and deletes the record, while code that trusts its own bytes
        waits, times out, and keeps it.
        """

        class _Client(FakeClient):
            async def broadcast(self, raw_tx: bytes) -> str:
                self.broadcasts.append(raw_tx)
                self.calls.append("broadcast")
                return cls.LIE

            async def get_transaction_verbose(self, txid: str) -> dict:
                # Confirm the COMMIT (identified by hashing what we were actually handed)
                # and the LIE. Everything else — including the real reveal — never
                # confirms, unconditionally.
                #
                # An earlier version of this claimed to "confirm ONLY the lie" and did
                # not: its commit clause iterated an empty tuple, so it was dead, and the
                # fallback confirmed EVERY txid until a second broadcast had happened.
                # The commit therefore confirmed by accident of call order. That is the
                # same defect this fixture exists to catch, reproduced inside the fixture.
                from pyrxd.transaction.transaction import Transaction

                confirmed = {cls.LIE} | {Transaction.from_hex(b.hex()).txid() for b in self.broadcasts[:1]}
                return {"confirmations": 1 if txid in confirmed else 0}

        return _Client()

    async def test_a_lying_echo_does_not_confirm_someone_elses_transaction(self):
        """THE case the previous fixture could not see.

        The record's protection is the confirmation wait. If that wait polls the
        server's echo, a server can drop the reveal, name an already-confirmed txid, and
        the record is deleted for a transaction that never relayed. Waiting on the
        locally derived txid is what makes the guard real — so a lying echo must NOT
        produce a confirmed reveal against the wrong txid.
        """
        store = RecordingStore()
        client = self._lying_client()
        minter = GlyphMinter(client, FakeWallet(_key()), store, confirmation_timeout_s=0.2)
        pending = await minter.commit_nft(_nft_metadata())

        with pytest.warns(UserWarning, match="echoed txid"):
            with pytest.raises(Exception):
                await minter.reveal_nft(pending)

        assert store.load(pending.commit_txid) is not None, "record deleted on a lie"

    async def test_a_stale_sub_floor_rate_is_refused_but_recoverable(self):
        """A commit priced below the CURRENT floor must fail loudly, not silently relay
        into a mempool that will drop it — and must stay revealable.

        The rate is now judged in ``__init__``, so a minter cannot be BUILT below the
        floor. The scenario this pins is the one that survives that gate: a commit made
        while the floor was lower, revealed after it rose. The stale rate therefore lives
        on the stored record, not on the minter — which is exactly where a real one would
        be, since ``PendingMint.fee_rate`` is captured at commit time.

        Refusing with no way through would be worse than the bug: the commit was funded at
        the old rate, so re-pricing upward is not always affordable. Hence
        ``allow_below_relay_floor=True``.
        """
        import dataclasses

        store = RecordingStore()
        minter = GlyphMinter(FakeClient(), FakeWallet(_key()), store)
        pending = await minter.commit_nft(_nft_metadata())

        # The floor rose after the commit: the record's captured rate is now sub-floor.
        stale = dataclasses.replace(pending, fee_rate=1)
        store.save(stale)

        with pytest.raises((ValidationError, ValueError), match="floor|relay"):
            await minter.reveal_nft(stale)
        assert store.load(stale.commit_txid) is not None, "a refusal must keep the record"

        # The escape hatch: send it anyway, deliberately.
        result = await minter.reveal_nft(stale, allow_below_relay_floor=True)
        assert result.reveal_txid
