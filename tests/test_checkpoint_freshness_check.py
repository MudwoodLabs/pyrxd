"""The scheduled checkpoint-freshness job: its decision, offline, and the workflow that runs it.

``scripts/check_checkpoint_freshness.py`` needs the network, so the scheduled job
(``.github/workflows/checkpoint-freshness.yml``) is the only thing that runs it for real. What is
tested here is everything that does not need the network: which tip decides, where the line is,
that a check that could not run is never read as a fresh table, and that the workflow is scheduled,
read-only and actually runs the script.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

from pyrxd.glyph.mark_block import MAX_HEADERS_FROM_CHECKPOINT
from pyrxd.gravity.funding_spv import MAX_HEADERS_FROM_CHECKPOINT_SDK
from pyrxd.spv.radiant_checkpoints import CHECKPOINTS

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_checkpoint_freshness", ROOT / "scripts" / "check_checkpoint_freshness.py"
)
assert _spec and _spec.loader
fresh = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = fresh  # a dataclass resolves its module by name
_spec.loader.exec_module(fresh)
_rspec = importlib.util.spec_from_file_location(
    "refresh_radiant_checkpoints", ROOT / "scripts" / "refresh_radiant_checkpoints.py"
)
assert _rspec and _rspec.loader
refresh = importlib.util.module_from_spec(_rspec)
_rspec.loader.exec_module(refresh)

WORKFLOW = ROOT / ".github" / "workflows" / "checkpoint-freshness.yml"
NEWEST = CHECKPOINTS["mainnet"][-1][0]
#: The last tip at which the job still passes: exactly WARN_BLOCKS left before the page horizon.
LAST_OK = NEWEST + MAX_HEADERS_FROM_CHECKPOINT - fresh.WARN_BLOCKS


def _assess(tips):
    return fresh.assess(
        tips, newest_checkpoint=NEWEST, page_cap=MAX_HEADERS_FROM_CHECKPOINT, sdk_cap=MAX_HEADERS_FROM_CHECKPOINT_SDK
    )


def test_the_line_is_864_blocks_before_the_pages_horizon() -> None:
    assert fresh.WARN_BLOCKS == 864 and MAX_HEADERS_FROM_CHECKPOINT == 4032
    ok = _assess({"a": LAST_OK})
    assert ok.code == 0 and ok.message.startswith("OK:") and f"{fresh.WARN_BLOCKS} block(s) from the tip" in ok.message
    near = _assess({"a": LAST_OK + 1})
    assert near.code == 1 and "is near" in near.message
    gone = _assess({"a": NEWEST + MAX_HEADERS_FROM_CHECKPOINT + 1})
    assert gone.code == 1 and "has PASSED" in gone.message


def test_a_failure_names_the_refresh_command_with_the_node() -> None:
    v = _assess({"a": LAST_OK + 1})
    assert "scripts/refresh_radiant_checkpoints.py --write --node-cli" in v.message
    assert "before the next release" in v.message


def test_the_highest_tip_decides_and_one_server_down_does_not_hide_it() -> None:
    v = _assess({"behind": NEWEST + 10, "down": None, "ahead": LAST_OK + 1})
    assert v.code == 1 and f"tip {LAST_OK + 1} (from ahead)" in v.message


@pytest.mark.parametrize(
    "tips",
    [{}, {"a": None, "b": None}, {"a": NEWEST - 1}, {"a": "469000"}, {"a": True}],
    ids=["none-asked", "none-answered", "below-the-checkpoint", "not-an-int", "a-bool"],
)
def test_a_check_that_could_not_run_is_red_and_never_reads_as_fresh(tips) -> None:
    v = _assess(tips)
    assert v.code == 2 and "NOT a fresh table" in v.message


def test_main_reads_the_shipped_table_and_exits_with_the_verdict(monkeypatch, capsys) -> None:
    """The production entry point, with the network replaced by the tips it would have read."""

    async def tips(urls):
        assert urls and all(u.startswith("wss://") for u in urls), urls
        return dict.fromkeys(urls, LAST_OK + 1)

    monkeypatch.setattr(fresh, "_tips", tips)
    assert fresh.main([]) == 1
    out = capsys.readouterr().out
    assert out.startswith("::error::The checkpoint horizon is near") and f"newest shipped checkpoint {NEWEST}" in out

    async def ok(urls):
        return dict.fromkeys(urls, LAST_OK)

    monkeypatch.setattr(fresh, "_tips", ok)
    assert fresh.main([]) == 0
    assert "::error::" not in capsys.readouterr().out


# --------------------------------------------------------------------------- the workflow


def _workflow() -> dict:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


def test_the_job_is_scheduled_daily_off_the_hour() -> None:
    on = _workflow()[True]  # YAML 1.1 reads a bare `on` as True
    crons = [c["cron"] for c in on["schedule"]]
    assert len(crons) == 1
    minute, hour, dom, month, dow = crons[0].split()
    assert (dom, month, dow) == ("*", "*", "*"), "daily"
    assert re.fullmatch(r"\d+", minute) and int(minute) != 0, "off the hour"
    assert re.fullmatch(r"\d+", hour)
    assert "workflow_dispatch" in on


def test_the_job_is_read_only_and_holds_no_secret() -> None:
    doc = _workflow()
    assert doc["permissions"] == {"contents": "read"}
    jobs = doc["jobs"]
    assert jobs and all(j.get("permissions") == {"contents": "read"} for j in jobs.values())
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text and "GITHUB_TOKEN" not in text


def test_the_job_runs_the_script_and_a_pr_touching_it_runs_the_job() -> None:
    doc = _workflow()
    runs = [s.get("run", "") for j in doc["jobs"].values() for s in j["steps"]]
    assert any("scripts/check_checkpoint_freshness.py" in r for r in runs), runs
    # Nothing may swallow the script's exit code (no `|| true`, no pipe).
    script_steps = [r for r in runs if "check_checkpoint_freshness" in r]
    assert all("||" not in r and "|" not in r for r in script_steps), script_steps
    paths = doc[True]["pull_request"]["paths"]
    assert "scripts/check_checkpoint_freshness.py" in paths and ".github/workflows/checkpoint-freshness.yml" in paths


def test_the_release_runbook_says_to_refresh_the_checkpoints_with_the_node() -> None:
    text = " ".join((ROOT / "docs" / "runbooks" / "cutting-a-release.md").read_text(encoding="utf-8").split())
    assert "scripts/refresh_radiant_checkpoints.py --write" in text and '--node-cli "<command that runs' in text
    assert "maintainer's node right before the release" in text


# --------------------------------------------------------------------------- a refresh always turns it green


@pytest.mark.parametrize(
    "min_depth", [refresh.DEFAULT_MIN_DEPTH, refresh.MAX_MIN_DEPTH], ids=["default", "deepest-allowed"]
)
def test_every_refresh_turns_the_job_green_and_it_goes_red_with_notice_before_the_horizon(min_depth) -> None:
    """Review finding (MEDIUM): with checkpoints 2,016 apart and a refresh min-depth of 1,000, a fresh
    table left the newest checkpoint up to 3,015 blocks below the tip, and the job went red past
    2,016 — so about half of all refreshes left it red at once. Swept over every refresh tip across
    three checkpoint intervals, through the refresh script's own height rule: the table it writes
    is green at that tip, stays green for at least the worst-case window, and goes red exactly
    WARN_BLOCKS before the pages' horizon."""
    interval, horizon_blocks, warn = refresh.INTERVAL, MAX_HEADERS_FROM_CHECKPOINT, fresh.WARN_BLOCKS
    worst_green = horizon_blocks - warn - (min_depth + interval - 1)
    assert worst_green >= 288, "the arithmetic: a refresh at this depth can leave the job green for under a day"
    base = 467_712
    for tip in range(base, base + 3 * interval + 1):
        newest = refresh.checkpoint_heights(tip, min_depth)[-1]

        def code(t, newest=newest):
            return fresh.assess(
                {"s": t}, newest_checkpoint=newest, page_cap=horizon_blocks, sdk_cap=MAX_HEADERS_FROM_CHECKPOINT_SDK
            ).code

        assert code(tip) == 0, (tip, newest)  # green right after the refresh
        first_red = newest + horizon_blocks - warn + 1
        assert first_red - tip >= worst_green  # green for at least the worst-case window
        assert code(first_red - 1) == 0 and code(first_red) == 1
        assert newest + horizon_blocks - first_red + 1 == warn  # red with WARN_BLOCKS of notice


def test_the_refresh_refuses_a_min_depth_that_could_leave_the_job_red(capsys) -> None:
    for bad in (refresh.MAX_MIN_DEPTH + 1, 1000 + 2016, refresh.MAX_REORG_DEPTH):
        with pytest.raises(SystemExit):
            refresh.main(["--check", "--min-depth", str(bad)])
        assert "--min-depth must be" in capsys.readouterr().err
