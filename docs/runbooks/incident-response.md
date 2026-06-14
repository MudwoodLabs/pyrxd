# Security incident-response runbook

The internal procedure for handling a vulnerability reported to
**security@mudwoodlabs.com**. The public-facing policy (where to report,
what to include, the response SLA) lives in
[`SECURITY.md`](../../SECURITY.md); this runbook is the maintainer's
checklist for what happens *after* a report lands.

## Why this exists

pyrxd is a single-maintainer project handling cryptographic and
value-bearing code. Without a written procedure, response to a report is
ad-hoc and the SLA in `SECURITY.md` (acknowledge within 2 business days,
assess within 7, coordinate disclosure within ~90) is easy to miss under
pressure. This runbook makes the steps mechanical so the right things
happen in the right order, even for the first real report.

## Severity guide

Use this to set urgency and the disclosure clock. When in doubt, round up.

| Severity | Examples | Target fix window |
|---|---|---|
| **Critical** | Key/seed exfiltration; a forged SPV proof or REF that drains a Maker; signing the wrong tx; a covenant bypass that steals an in-flight swap | Days; consider an out-of-band advisory |
| **High** | Fee/value miscalculation that loses funds; a broadcast-path crash that strands a confirmed commit; auth/confirmation-gate bypass | ~2 weeks |
| **Medium** | Information leak (key bytes in a traceback/log); a fail-*open* default where a control must be explicitly enabled | Next scheduled release |
| **Low / Info** | Hardening gaps, missing warnings, defense-in-depth | Backlog |

The trust boundaries and current accepted residuals are in
[`docs/threat-model.md`](../threat-model.md) — read the relevant scenario
(S1–S20) before assessing impact.

## The flow

### 1. Acknowledge (≤ 2 business days)

Reply to the reporter from `security@mudwoodlabs.com`: confirm receipt,
give a tracking handle, and ask for anything missing (repro steps,
affected versions). Do **not** discuss the issue in a public channel,
issue, or PR.

### 2. Triage + reproduce (≤ 7 business days for the initial assessment)

- Reproduce it. If you can't, say so to the reporter and ask for more.
- Set severity (table above) and the affected version range.
- Open a **private** GitHub Security Advisory (Security tab →
  "Report a vulnerability" → draft): `gh api
  repos/MudwoodLabs/pyrxd/security-advisories -f summary=… -f severity=…`.
  The advisory is the private workspace; it can request a CVE and spin a
  private fork for the fix when ready.

### 3. Fix privately

- Branch from the advisory's private fork (or a local branch you do **not**
  push to a public branch). Conventional-commit scope `fix(security):` —
  but keep the message non-specific until disclosure.
- **Write a regression test that fails before the fix** (the project rule;
  for a value/assembly bug, a build→fee→sign or consensus-path test).
- Run `task ci` locally. Patch the lowest still-supported affected version
  if a backport is warranted (see `SECURITY.md` → Supported Versions).

### 4. Coordinate disclosure

- Agree a disclosure date with the reporter (default ≤ 90 days, sooner for
  Critical). If the bug is being actively exploited, shorten it.
- Request the CVE via the advisory if the issue warrants a public
  identifier (most Critical/High do).

### 5. Release the fix

- Bump `pyproject.toml`, update `CHANGELOG.md` (crediting the reporter
  unless they opted out).
- Cut a GitHub Release → this triggers
  [`.github/workflows/publish.yml`](../../.github/workflows/publish.yml)
  (OIDC Trusted Publishing + PEP 740 attestations + the CycloneDX SBOM).
- Verify the new version is on PyPI with its provenance attestation.

### 6. Publish + notify

- Publish the GitHub Security Advisory (this is the public disclosure).
- Confirm to the reporter that it's out; thank them.
- If a config/usage change is needed by users, note it in the advisory and
  the release notes.
- Update [`docs/threat-model.md`](../threat-model.md): close the gap or add
  the new scenario, and record any newly-accepted residual.

## After-action

For anything Critical/High, write a short
[`docs/solutions/`](../solutions/) note: the root cause, why existing tests
missed it, and the test class that now guards it — so the same class of
bug can't recur silently.
