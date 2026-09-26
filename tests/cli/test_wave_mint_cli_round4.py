"""``glyph resume-mint``, PR #742 round 4: lane D N1 on ``954b8d92``.

Round 3 kept ``chmod`` off a symlinked ``done/`` on the WRITE path. The READ path still took
it: ``resume-mint`` read an archived record with ``load_archived`` BEFORE its ``lstat``
refusal, and ``load_archived`` built a second store on ``done/`` whose constructor chmodded the
directory by path. So a ``done/`` that was a link to a 0755 directory holding the archived
record was refused, correctly, and the foreign directory was left 0700.

Now ``resume-mint`` refuses an unusable ``done/`` before it reads any record, and the library
reads the archive only through a descriptor opened with ``O_NOFOLLOW``. The foreign directory
here is 0500, not 0755: CodeQL flags a world-readable ``chmod`` even in a test, and any mode
other than 0700 shows a chmod.
"""

from __future__ import annotations

import os
import pathlib
import stat

import pytest

from .test_wave_mint_cli_round2 import _archived, _said, _use, _WithholdsTheReveal
from .test_wave_registration_fee_cli import _PAY, _TREASURY_SCRIPT, _mint, _record_path, _resume, _scripts, _tx, _wire

_FOREIGN_MODE = 0o500
_POSIX = pytest.mark.skipif(os.name != "posix", reason="file modes and symbolic links as POSIX has them")


@_POSIX
class TestReadingTheArchiveNeverFollowsALink:
    def test_resume_mint_refuses_a_linked_archive_before_reading_it_and_goes_ahead_once_it_is_real(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        # Lane D's setup: the record is archived (a server reported a withheld reveal confirmed),
        # then done/ becomes a link to a foreign directory holding it; no live record.
        liar = _WithholdsTheReveal(chain)
        _use(monkeypatch, liar)
        fooled = _mint(tmp_path, "abcde")
        assert fooled.exit_code == 0, fooled.output
        txid = str(_tx(chain.broadcasts[0]).txid())
        done = _archived(tmp_path, txid).parent
        foreign = tmp_path / "somebody-elses"
        os.replace(done, foreign)
        os.chmod(foreign, _FOREIGN_MODE)
        done.symlink_to(foreign, target_is_directory=True)
        assert not _record_path(tmp_path, txid).exists()

        _use(monkeypatch, chain)
        polls: list[str] = []
        chain.on_poll = polls.append
        refused = _resume(tmp_path, txid, _PAY)
        chain.on_poll = None
        # The property lane D broke: on 954b8d92 this was 0700 after the (correct) refusal.
        assert stat.S_IMODE(foreign.stat().st_mode) == _FOREIGN_MODE
        assert [p.name for p in foreign.iterdir()] == [f"{txid}.json"]
        assert refused.exit_code == 1 and len(chain.broadcasts) == 1 and polls == []
        said = _said(refused)
        assert "is unusable — NOT broadcasting the reveal" in said and "is a symbolic link" in said

        # Honest path: made a real directory again, the archived record is found and revealed.
        done.unlink()
        os.chmod(foreign, 0o700)
        os.replace(foreign, done)
        finished = _resume(tmp_path, txid, _PAY)
        assert finished.exit_code == 0, finished.output
        reveal = _tx(chain.broadcasts[1])
        assert (reveal.inputs[0].source_txid, reveal.inputs[0].source_output_index) == (txid, 0)
        assert _scripts(reveal).count(_TREASURY_SCRIPT) == 1
        assert _archived(tmp_path, txid).exists() and not _record_path(tmp_path, txid).exists()

    def test_a_txid_with_no_record_and_a_linked_archive_is_refused_without_listing_through_it(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        chain, _wallet = _wire(monkeypatch)
        (tmp_path / "pending-mints").mkdir(mode=0o700)
        foreign = tmp_path / "somebody-elses"
        foreign.mkdir()
        os.chmod(foreign, _FOREIGN_MODE)
        (tmp_path / "pending-mints" / "done").symlink_to(foreign, target_is_directory=True)
        refused = _resume(tmp_path, "ab" * 32, _PAY)
        assert refused.exit_code == 1 and chain.broadcasts == []
        assert stat.S_IMODE(foreign.stat().st_mode) == _FOREIGN_MODE
        assert "is a symbolic link" in _said(refused)
