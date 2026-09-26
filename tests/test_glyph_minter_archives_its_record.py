"""The SDK sibling of #736 (PR #742 round 3): ``GlyphMinter`` archives a record, never deletes it.

``GlyphMinter`` retires the pending record once its reveal is reported confirmed. "Confirmed" is
the server's word, and a server can echo a reveal it never relayed and report it confirmed —
lane D's withheld-reveal route against the CLI. The minter used to ``delete()`` the record at
that point: the only copy of the payload the still-unspent commit can be spent with. It now calls
:meth:`~pyrxd.glyph.mint.PendingStore.archive`, which :class:`JsonFilePendingStore` implements as
a move to ``done/``, and the public ``delete()`` keeps its documented meaning for callers who
want it.

The archive must be usable before anything is broadcast (lane D F2, round 3): ``done/`` that is
a regular file or a symbolic link is refused before the commit and again before the reveal, the
library ``archive()`` never ``chmod``s through a link, and an archive that still fails after a
reported confirmation is a warning, not an error.

The client and wallet doubles are ``test_glyph_mint_facade.py``'s.
"""

from __future__ import annotations

import os
import pathlib
import stat

import pytest
from test_glyph_mint_facade import FakeClient, FakeWallet, RecordingStore, _key, _nft_metadata

from pyrxd.glyph.mint import GlyphMinter, JsonFilePendingStore, PendingMint, PendingMintNotFound, PendingStore
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction


class _WithholdsTheReveal(FakeClient):
    """Relays the commit, echoes the reveal's txid WITHOUT relaying it, and reports it confirmed."""

    def __init__(self) -> None:
        super().__init__()
        self.withheld: list[str] = []

    async def broadcast(self, raw_tx: bytes) -> str:
        if self.broadcasts:  # the commit went out first; this is the reveal
            txid = Transaction.from_hex(raw_tx.hex()).txid()
            self.withheld.append(str(txid))
            return txid
        return await super().broadcast(raw_tx)


class _RefusesDelete(RecordingStore):
    """A store where a minter calling ``delete()`` is a test failure."""

    def delete(self, commit_txid: str) -> None:
        raise AssertionError(f"GlyphMinter called delete({commit_txid}) — it must archive")


class _CannotArchive(PendingStore):
    """A store that implements only the abstract methods: ``archive`` is the base default."""

    def __init__(self) -> None:
        self.records: dict[str, PendingMint] = {}
        self.deleted: list[str] = []

    def save(self, pending: PendingMint) -> None:
        self.records[pending.commit_txid] = pending

    def load(self, commit_txid: str) -> PendingMint:
        try:
            return self.records[commit_txid]
        except KeyError:
            raise PendingMintNotFound(commit_txid) from None

    def delete(self, commit_txid: str) -> None:
        self.deleted.append(commit_txid)
        self.records.pop(commit_txid, None)

    def list_pending(self) -> list[str]:
        return sorted(self.records)


async def test_a_reveal_a_server_withheld_leaves_an_archived_record_another_server_finishes(
    tmp_path: pathlib.Path,
) -> None:
    key = _key()
    store = JsonFilePendingStore(tmp_path)
    liar = _WithholdsTheReveal()
    fooled = await GlyphMinter(liar, FakeWallet(key), store).mint_nft(_nft_metadata())
    # The minter was told the reveal confirmed, and it never reached a node:
    assert liar.withheld == [fooled.reveal_txid] and len(liar.broadcasts) == 1
    txid = fooled.commit_txid
    # Before round 3 the record was deleted here, with the commit still unspent: no file left.
    assert [p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*.json")] == [f"done/{txid}.json"]
    assert store.list_pending() == [] and store.list_archived() == [txid]
    pending = store.load_archived(txid)

    honest = FakeClient()
    finished = await GlyphMinter(honest, FakeWallet(key), store).reveal_nft(pending)
    reveal = Transaction.from_hex(honest.broadcasts[0].hex())
    assert (reveal.inputs[0].source_txid, reveal.inputs[0].source_output_index) == (txid, 0)
    assert pending.cbor_bytes in reveal.inputs[0].unlocking_script.serialize()
    assert finished.reveal_txid == fooled.reveal_txid  # the same signed reveal, deterministic
    assert store.list_archived() == [txid]


async def test_an_honest_mint_archives_its_record(tmp_path: pathlib.Path) -> None:
    store = JsonFilePendingStore(tmp_path)
    result = await GlyphMinter(FakeClient(), FakeWallet(_key()), store).mint_nft(_nft_metadata())
    assert store.list_pending() == [] and store.list_archived() == [result.commit_txid]
    with pytest.raises(PendingMintNotFound):
        store.load(result.commit_txid)
    assert store.load_archived(result.commit_txid).commit_txid == result.commit_txid
    if os.name == "posix":
        archived = store.archive_directory / f"{result.commit_txid}.json"
        assert stat.S_IMODE(archived.stat().st_mode) == 0o600
        assert stat.S_IMODE(store.archive_directory.stat().st_mode) == 0o700


async def test_the_minter_never_calls_delete_on_a_completed_mint() -> None:
    store = _RefusesDelete()
    result = await GlyphMinter(FakeClient(), FakeWallet(_key()), store).mint_nft(_nft_metadata())
    assert store.list_pending() == [] and list(store.archived) == [result.commit_txid]
    assert "delete" not in store.log


async def test_a_store_that_cannot_archive_keeps_the_record() -> None:
    """The base ``archive`` errs toward keeping: the record stays listed, and nothing is deleted."""
    store = _CannotArchive()
    result = await GlyphMinter(FakeClient(), FakeWallet(_key()), store).mint_nft(_nft_metadata())
    assert store.list_pending() == [result.commit_txid] and store.deleted == []


def test_delete_keeps_its_documented_meaning(tmp_path: pathlib.Path) -> None:
    from test_glyph_mint_facade import _pending

    store = JsonFilePendingStore(tmp_path)
    record = _pending()
    store.save(record)
    store.delete(record.commit_txid)
    assert store.list_pending() == [] and store.list_archived() == []
    with pytest.raises(PendingMintNotFound):
        store.load_archived(record.commit_txid)


def test_archive_and_restore_round_trip(tmp_path: pathlib.Path) -> None:
    from test_glyph_mint_facade import _pending

    store = JsonFilePendingStore(tmp_path)
    record = _pending()
    store.save(record)
    store.archive(record.commit_txid)
    store.archive(record.commit_txid)  # already archived: nothing to do, no error
    assert store.list_pending() == [] and store.load_archived(record.commit_txid) == record
    store.restore(record.commit_txid)
    assert store.list_pending() == [record.commit_txid] and store.list_archived() == []
    assert store.load(record.commit_txid) == record


# ─── lane D F2 (round 3): an archive that cannot take the record is found BEFORE a broadcast ──

_POSIX = pytest.mark.skipif(os.name != "posix", reason="file modes and symbolic links as POSIX has them")


def _foreign(tmp_path: pathlib.Path) -> pathlib.Path:
    """A directory that is not the store's, 0755."""
    foreign = tmp_path / "somebody-elses"
    foreign.mkdir()
    os.chmod(foreign, 0o755)
    return foreign


def _spoil(store_dir: pathlib.Path, tmp_path: pathlib.Path, shape: str) -> pathlib.Path | None:
    store_dir.mkdir(exist_ok=True)
    done = store_dir / "done"
    if shape == "file":
        done.write_text("not a directory")
        return None
    foreign = _foreign(tmp_path)
    done.symlink_to(foreign, target_is_directory=True)
    return foreign


_PROBLEM = {"file": "exists and is not a directory", "symlink": "is a symbolic link"}


@_POSIX
@pytest.mark.parametrize("shape", ["file", "symlink"])
def test_archive_refuses_and_keeps_the_record_without_touching_a_link_target(
    tmp_path: pathlib.Path, shape: str
) -> None:
    from test_glyph_mint_facade import _pending

    store = JsonFilePendingStore(tmp_path / "pm")
    record = _pending()
    store.save(record)
    foreign = _spoil(tmp_path / "pm", tmp_path, shape)
    assert store.archive_problem() is not None and _PROBLEM[shape] in store.archive_problem()
    with pytest.raises(ValidationError, match=_PROBLEM[shape]):
        store.archive(record.commit_txid)
    assert store.list_pending() == [record.commit_txid]
    if foreign is not None:
        # chmod follows links: before round 3 this was 0700, and the record had moved into it.
        assert stat.S_IMODE(foreign.stat().st_mode) == 0o755 and list(foreign.iterdir()) == []


@_POSIX
def test_a_link_swapped_in_after_the_lstat_is_not_followed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``lstat`` check is not what keeps the chmod and the rename off a link: they act on a
    descriptor opened with ``O_NOFOLLOW``. Here the check is blinded (a link appears after it),
    and the archive still refuses without touching the link's target."""
    from test_glyph_mint_facade import _pending

    store = JsonFilePendingStore(tmp_path / "pm")
    record = _pending()
    store.save(record)
    foreign = _spoil(tmp_path / "pm", tmp_path, "symlink")
    monkeypatch.setattr(JsonFilePendingStore, "archive_problem", lambda self: None)
    with pytest.raises(ValidationError, match="could not be opened as a real directory"):
        store.archive(record.commit_txid)
    assert store.list_pending() == [record.commit_txid]
    assert foreign is not None and stat.S_IMODE(foreign.stat().st_mode) == 0o755
    assert list(foreign.iterdir()) == []


@_POSIX
@pytest.mark.parametrize("shape", ["file", "symlink"])
async def test_the_minter_refuses_before_the_commit_when_the_archive_is_unusable(
    tmp_path: pathlib.Path, shape: str
) -> None:
    store = JsonFilePendingStore(tmp_path / "pm")
    foreign = _spoil(tmp_path / "pm", tmp_path, shape)
    client = FakeClient()
    with pytest.raises(ValidationError, match="archive is unusable.*the commit was not broadcast; fix it and retry"):
        await GlyphMinter(client, FakeWallet(_key()), store).mint_nft(_nft_metadata())
    assert client.broadcasts == [] and store.list_pending() == []
    if foreign is not None:
        assert stat.S_IMODE(foreign.stat().st_mode) == 0o755


@_POSIX
async def test_the_minter_refuses_before_the_reveal_when_the_archive_went_bad_after_the_commit(
    tmp_path: pathlib.Path,
) -> None:
    store = JsonFilePendingStore(tmp_path / "pm")
    client = FakeClient()
    minter = GlyphMinter(client, FakeWallet(_key()), store)
    pending = await minter.commit_nft(_nft_metadata())
    assert len(client.broadcasts) == 1
    _spoil(tmp_path / "pm", tmp_path, "file")
    with pytest.raises(
        ValidationError, match="archive is unusable.*the reveal was not broadcast and the record is kept"
    ):
        await minter.reveal_nft(pending)
    assert len(client.broadcasts) == 1 and store.list_pending() == [pending.commit_txid]


class _ArchiveBreaksAfterTheCheck(JsonFilePendingStore):
    """Passes the pre-broadcast check, then fails to archive: a rename across filesystems."""

    def archive(self, commit_txid: str) -> None:
        raise OSError(18, "Invalid cross-device link")


async def test_an_archive_failure_after_a_reported_confirmation_warns_and_keeps_the_record(
    tmp_path: pathlib.Path,
) -> None:
    store = _ArchiveBreaksAfterTheCheck(tmp_path)
    with pytest.warns(UserWarning, match="could not be archived .*Invalid cross-device link.*kept where it was"):
        result = await GlyphMinter(FakeClient(), FakeWallet(_key()), store).mint_nft(_nft_metadata())
    assert result.reveal_txid and store.list_pending() == [result.commit_txid]
