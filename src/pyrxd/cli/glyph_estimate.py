"""``pyrxd glyph dmint-estimate`` — benchmark this machine, estimate a mint.

Answers "should I bother mining this contract?" before the grind starts,
and (via :class:`_MiningReporter`) keeps answering it while the grind
runs. The arithmetic lives in :mod:`pyrxd.glyph.dmint.estimate`; this
module is presentation plus the network lookup.

The output's three-way split is the point, not decoration — this repo
does not let a projection be printed as if it were a measurement:

* **MEASURED** — the single-core SHA256d rate, benchmarked here, now,
  on the same hash chain the miner runs. During a grind, the observed
  aggregate rate (also measured — the miner really achieved it).
* **EXACT** — ``p``, mean attempts, and the attempt quantiles. Closed
  form from the verifier predicate; no measurement, no assumption.
* **PROJECTED** — every ETA, and the pre-grind aggregate rate. That
  aggregate is ``single-core × workers``, and **cross-core scaling is
  not measured**, so it reads high on real hardware.

In ``--json`` those are three separate top-level keys and stay that
way; ``tests/cli/test_glyph_estimate_cmds.py`` fails the build if an ETA
ever migrates into the measured block.

The command object is built with a bare ``@click.command`` and attached
to the ``glyph`` group by :mod:`pyrxd.cli.glyph_cmds` via
``glyph_group.add_command(dmint_estimate_cmd)``.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import TYPE_CHECKING

import click

from ..glyph.dmint import (
    DEFAULT_BENCHMARK_SECONDS,
    benchmark_sha256d,
    difficulty_to_target,
    estimate_attempts,
    live_stats,
    project_mint_eta,
)
from ..security.errors import NetworkError, ValidationError
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit
from .glyph_helpers import _fetch_dmint_contract, _parse_ref

if TYPE_CHECKING:
    from ..glyph.dmint import AttemptEstimate, DmintContractUtxo

__all__ = [
    "dmint_estimate_cmd",
]

# Seconds between rendered progress lines during a grind. The miner calls the
# reporter far more often than this (it doubles as the deadline check); this
# only rate-limits what reaches the terminal.
_PRINT_INTERVAL_S = 2.0

_SI_UNITS = ("", "k", "M", "G", "T", "P", "E")


class MiningDeadline(Exception):
    """Raised out of the progress callback when a grind's wall clock expires.

    Raising from inside the callback is the documented way to stop
    ``mine_solution`` / ``pyrxd.contrib.miner.parallel.mine``: it unwinds
    through the miner's worker-cleanup context, so no worker survives the
    abort. Callers translate it into the same
    :class:`~pyrxd.security.errors.MaxAttemptsError` an external miner's
    timeout produces, so downstream reroll logic does not have to care
    which miner was in use.
    """


def _format_count(n: float) -> str:
    """Render a count with an SI-ish suffix (``8.59 G``, or ``872`` when small)."""
    scaled = float(n)
    for unit in _SI_UNITS:
        if scaled < 1000 or unit == _SI_UNITS[-1]:
            return f"{scaled:,.2f} {unit}" if unit else f"{scaled:,.0f}"
        scaled /= 1000
    raise AssertionError("unreachable: the loop returns on the last unit")  # pragma: no cover


def _format_rate(hashes_per_second: float) -> str:
    """Render a hash rate (``1.74 Mh/s``, ``872 h/s``)."""
    counted = _format_count(hashes_per_second)
    return f"{counted}h/s" if counted[-1] in "kMGTPE" else f"{counted} h/s"


def _format_duration(seconds: float) -> str:
    """Render a duration at a sensible granularity (``7m 07s``, ``2.4 years``)."""
    if seconds != seconds or seconds in (float("inf"), float("-inf")):  # NaN / inf
        return "unknown"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60):02d}s"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60):02d}m"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    return f"{seconds / (86400 * 365):.1f} years"


class _MiningReporter:
    """Live-progress callback for a mining grind — and its deadline.

    Two jobs, deliberately in one object because both need the same
    ``callback(attempts, elapsed_s)`` seam the miners expose:

    1. Render a rate-limited progress line to **stderr** (stdout stays
       clean for ``--json``).
    2. Enforce the wall-clock deadline by raising :class:`MiningDeadline`.
       Both miners document that a raising callback propagates with worker
       cleanup intact, which is what makes this safe.

    The rendered line reports the **observed** aggregate rate — measured,
    not projected — and remaining-time quantiles derived from it. Those
    quantiles do not tick down as attempts accumulate, because the process
    is memoryless; the header says so once, so nobody reads the line as a
    countdown.
    """

    def __init__(
        self,
        estimate: AttemptEstimate,
        *,
        enabled: bool,
        deadline_s: float | None,
        print_interval_s: float = _PRINT_INTERVAL_S,
        clock=time.monotonic,
    ) -> None:
        self._estimate = estimate
        self._enabled = enabled
        self._clock = clock
        self._print_interval_s = print_interval_s
        self._deadline = None if deadline_s is None else clock() + deadline_s
        self._next_print = 0.0
        self._header_shown = False
        self._line_len = 0

    def __call__(self, attempts: int, elapsed_s: float) -> None:
        now = self._clock()
        if self._deadline is not None and now >= self._deadline:
            raise MiningDeadline(f"mining deadline reached after {_format_duration(elapsed_s)}")
        if not self._enabled or now < self._next_print:
            return
        self._next_print = now + self._print_interval_s
        if not self._header_shown:
            self._header_shown = True
            for line in self._header():
                click.echo(line, err=True)
        self._emit(self._render(attempts, elapsed_s))

    def _header(self) -> list[str]:
        """The EXACT attempt distribution, stated once before the live lines."""
        est = self._estimate
        quantiles = ", ".join(f"p{int(q * 100)} {_format_count(n)}" for q, n in est.quantile_attempts)
        return [
            f"mining  difficulty {est.difficulty:,}  |  EXACT: mean {_format_count(est.expected_attempts)} "
            f"attempts ({quantiles})",
            "  'remaining' below is a memoryless distribution, not a countdown — it does not tick down.",
        ]

    def finish(self) -> None:
        """Close out the progress line so following output starts clean."""
        if self._enabled and self._line_len:
            click.echo("", err=True)
            self._line_len = 0

    def _render(self, attempts: int, elapsed_s: float) -> str:
        stats = live_stats(attempts, elapsed_s, self._estimate)
        head = f"mining  {_format_count(attempts)} attempts  elapsed {_format_duration(elapsed_s)}"
        if stats.remaining_mean_s is None:
            return f"{head}  (measuring…)"
        quantiles = "  ".join(f"p{int(q * 100)} {_format_duration(s)}" for q, s in stats.remaining_quantile_s)
        return (
            f"{head}  {_format_rate(stats.observed_hashes_per_second)} observed"
            f"  |  remaining: mean {_format_duration(stats.remaining_mean_s)}  {quantiles}"
        )

    def _emit(self, line: str) -> None:
        """One line per update on a pipe; an in-place rewrite on a terminal."""
        if not sys.stderr.isatty():
            # Already newline-terminated, so finish() has nothing to close out.
            click.echo(line, err=True)
            return
        pad = max(0, self._line_len - len(line))
        click.echo(f"\r{line}{' ' * pad}", err=True, nl=False)
        self._line_len = len(line)


def _resolve_target(
    contract_arg: str | None,
    token_ref_arg: str | None,
    target_arg: str | None,
    difficulty: int | None,
    ctx: CliContext,
) -> tuple[int, dict | None]:
    """Resolve exactly one locator to ``(target, contract_payload_or_None)``."""
    supplied = [a is not None for a in (contract_arg, token_ref_arg, target_arg, difficulty)]
    if sum(supplied) != 1:
        raise UserError(
            "pass exactly one of --contract, --token-ref, --target, or --difficulty",
            fix="e.g. --difficulty 1 for an offline estimate, or --contract TXID:VOUT for a live one",
        )

    if difficulty is not None:
        try:
            return difficulty_to_target(difficulty), None
        except ValidationError as exc:
            raise UserError("invalid --difficulty", cause=str(exc), fix="difficulty must be >= 1") from exc

    if target_arg is not None:
        try:
            target = int(target_arg, 0)
        except ValueError as exc:
            raise UserError(
                f"could not parse --target {target_arg!r}",
                cause=str(exc),
                fix="pass a decimal (9223372036854775807) or 0x-prefixed hex (0x7fffffffffffffff)",
            ) from exc
        if target < 1:
            raise UserError(f"--target must be >= 1, got {target}")
        return target, None

    contract_utxo = _fetch_contract(ctx, contract_arg, token_ref_arg)
    state = contract_utxo.state
    return state.target, {
        "contract": f"{contract_utxo.txid}:{contract_utxo.vout}",
        "version": "V1" if state.is_v1 else "V2",
        "height": state.height,
        "max_height": state.max_height,
        "reward": state.reward,
        "nonce_width": 4 if state.is_v1 else 8,
    }


def _fetch_contract(ctx: CliContext, contract_arg: str | None, token_ref_arg: str | None) -> DmintContractUtxo:
    """Read the live contract UTXO whose target we are estimating against."""
    # Imported here rather than at module scope: `chain` pulls the ElectrumX
    # client stack, and the offline --difficulty / --target paths must not pay
    # for it.
    from ..glyph.dmint import find_dmint_contract_utxos

    async def _read() -> DmintContractUtxo:
        client = ctx.make_client()
        async with client:
            if contract_arg is not None:
                ref = _parse_ref(contract_arg)
                return await _fetch_dmint_contract(client, str(ref.txid), ref.vout)
            tref = _parse_ref(token_ref_arg)  # type: ignore[arg-type]
            contracts = await find_dmint_contract_utxos(client, token_ref=tref)
            live = next((c for c in contracts if not c.state.is_exhausted), None)
            if live is None:
                raise UserError(
                    "no live (non-exhausted) dMint contract found for that token_ref",
                    fix="check the token_ref, or pass --contract TXID:VOUT directly",
                )
            return live

    try:
        return asyncio.run(_read())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable, or estimate offline with --difficulty",
        ) from exc


def _row(label: str, value: str) -> str:
    """One aligned ``label   value`` line of the human report."""
    return f"  {label:<17}{value}"


def _render_human(payload: dict) -> str:
    """Render the estimate with MEASURED / EXACT / PROJECTED kept apart."""
    exact = payload["exact"]
    projected = payload["projected"]
    lines: list[str] = []

    header = f"dMint mint estimate — difficulty {exact['difficulty']:,} (target {exact['effective_target']:#x})"
    lines.append(header)
    if exact["clamped"]:
        lines.append(
            f"  note: supplied target {exact['target']:#x} exceeds the ceiling and was clamped by the verifier"
        )

    contract = payload.get("contract")
    if contract:
        lines.append("")
        lines.append("CONTRACT (from the network)")
        lines.append(_row("contract", f"{contract['contract']} ({contract['version']})"))
        lines.append(_row("height", f"{contract['height']:,} / {contract['max_height']:,}"))
        lines.append(_row("reward", f"{contract['reward']:,} photons per mint"))

    measured = payload.get("measured")
    assumed = payload.get("assumed")
    lines.append("")
    if measured:
        lines.append("MEASURED (this machine, one core, just now)")
        lines.append(
            _row(
                "sha256d rate",
                f"{_format_rate(measured['single_core_hashes_per_second'])}"
                f"   ({measured['benchmark_hashes']:,} hashes in {measured['benchmark_elapsed_s']:.3f}s)",
            )
        )
    else:
        lines.append("ASSUMED (nothing was measured — you supplied this rate)")
        lines.append(_row("sha256d rate", f"{_format_rate(assumed['single_core_hashes_per_second'])} per core"))

    lines.append("")
    lines.append("EXACT (closed form from the target — not measured, not assumed)")
    lines.append(_row("hit probability", f"{exact['probability_per_attempt']:.6e} per hash   (p = target / 2^96)"))
    lines.append(_row("mean attempts", f"{_format_count(exact['expected_attempts'])}   (= 2^96 / target)"))
    for q, n in _quantile_pairs(exact["quantile_attempts"]):
        lines.append(_row(f"p{int(q * 100)} attempts", _format_count(n)))

    lines.append("")
    lines.append(
        f"PROJECTED (assumes linear scaling to {projected['workers']} workers — cross-core scaling is NOT measured)"
    )
    lines.append(_row("aggregate rate", _format_rate(projected["aggregate_hashes_per_second"])))
    lines.append(_row("mean ETA", _format_duration(projected["eta_mean_s"])))
    for q, s in _quantile_pairs(projected["eta_quantile_s"]):
        lines.append(_row(f"p{int(q * 100)} ETA", _format_duration(s)))

    lines.append("")
    lines.append("Mining is memoryless: attempts already spent do not shorten what remains.")
    lines.append("These are distribution quantiles, not a countdown.")
    return "\n".join(lines)


def _quantile_pairs(entries: list) -> list[tuple[float, float]]:
    """Normalise the JSON-shaped ``[{"quantile": q, ...}]`` back to pairs."""
    return [(e["quantile"], e["value"]) for e in entries]


@click.command(name="dmint-estimate")
@click.option("--contract", default=None, help="Live contract UTXO as TXID:VOUT — estimate against its current target.")
@click.option(
    "--token-ref",
    "token_ref",
    default=None,
    help="Token ref TXID:0 — estimate against its first live contract.",
)
@click.option(
    "--target",
    "target_arg",
    default=None,
    help="Offline: estimate against a raw target (decimal or 0x-hex).",
)
@click.option("--difficulty", type=int, default=None, help="Offline: estimate against a difficulty (target = MAX/N).")
@click.option("--workers", type=int, default=None, help="Workers to project across [default: one per logical CPU].")
@click.option(
    "--benchmark-seconds",
    type=float,
    default=DEFAULT_BENCHMARK_SECONDS,
    show_default=True,
    help="Seconds spent measuring this machine's single-core SHA256d rate.",
)
@click.option(
    "--hash-rate",
    type=float,
    default=None,
    help="Skip the benchmark and ASSUME this single-core h/s (e.g. to model a GPU miner). Output is then projected from an assumption, with nothing measured.",
)
@click.pass_obj
def dmint_estimate_cmd(
    ctx: CliContext,
    contract: str | None,
    token_ref: str | None,
    target_arg: str | None,
    difficulty: int | None,
    workers: int | None,
    benchmark_seconds: float,
    hash_rate: float | None,
) -> None:
    """Benchmark this machine's SHA256d rate and estimate time-to-mint.

    Reports three separate things and never blends them: the hash rate it
    MEASURED here, the attempt distribution it computed EXACTLY from the
    target, and the wall-clock ETAs it PROJECTED from the two (assuming
    linear scaling across workers, which is not measured).

    Mining is a geometric process and therefore memoryless, so the ETA is
    a mean plus quantiles — never a countdown. Read "p90 ETA 24m" as "one
    run in ten takes longer than 24 minutes", not "24 minutes left".

    \b
    Offline:  pyrxd glyph dmint-estimate --difficulty 1
    Live:     pyrxd glyph dmint-estimate --contract TXID:VOUT
    """
    from ..contrib.miner.parallel import default_n_workers

    target, contract_payload = _resolve_target(contract, token_ref, target_arg, difficulty, ctx)
    n_workers = default_n_workers() if workers is None else workers
    if n_workers < 1:
        raise UserError(f"--workers must be >= 1, got {n_workers}")
    if hash_rate is not None and hash_rate <= 0:
        raise UserError(f"--hash-rate must be positive, got {hash_rate}")

    estimate = estimate_attempts(target)

    measured: dict | None = None
    assumed: dict | None = None
    if hash_rate is None:
        try:
            bench = benchmark_sha256d(duration_s=benchmark_seconds)
        except ValidationError as exc:
            raise UserError("could not benchmark this machine", cause=str(exc)) from exc
        single_core = bench.hashes_per_second
        measured = {
            "single_core_hashes_per_second": single_core,
            "benchmark_hashes": bench.hashes,
            "benchmark_elapsed_s": bench.elapsed_s,
            "source": "benchmark",
        }
    else:
        single_core = hash_rate
        assumed = {"single_core_hashes_per_second": single_core, "source": "--hash-rate"}

    projection = project_mint_eta(estimate, single_core_hashes_per_second=single_core, workers=n_workers)

    payload = {
        "contract": contract_payload,
        # MEASURED: observed on this machine. Never contains an ETA.
        "measured": measured,
        # ASSUMED: caller-supplied rate. Mutually exclusive with "measured".
        "assumed": assumed,
        # EXACT: closed form from the target.
        "exact": {
            "target": estimate.target,
            "effective_target": estimate.effective_target,
            "clamped": estimate.clamped,
            "difficulty": estimate.difficulty,
            "probability_per_attempt": estimate.probability_per_attempt,
            "expected_attempts": estimate.expected_attempts,
            "quantile_attempts": [{"quantile": q, "value": n} for q, n in estimate.quantile_attempts],
        },
        # PROJECTED: everything downstream of an unmeasured scaling assumption.
        "projected": {
            "workers": projection.workers,
            "single_core_hashes_per_second": projection.single_core_hashes_per_second,
            "aggregate_hashes_per_second": projection.aggregate_hashes_per_second,
            "scaling_assumption": "linear across workers (NOT measured)",
            "eta_mean_s": projection.mean_s,
            "eta_quantile_s": [{"quantile": q, "value": s} for q, s in projection.quantile_s],
        },
    }

    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit({"eta_mean_s": projection.mean_s}, mode="quiet", quiet_field="eta_mean_s"))
    else:
        click.echo(_render_human(payload))
