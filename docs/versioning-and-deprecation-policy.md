# Versioning & deprecation policy

pyrxd follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — but "breaking" for an
**on-chain SDK** means more than a changed Python signature. This page defines what counts as breaking,
the pre-1.0 reality, and how deprecations are run, so downstream integrators know what a version bump
promises (and what it doesn't).

> _Draft for maintainer sign-off. The deprecation windows below are the proposed posture._

## What "breaking" means here

A change is **breaking-class** (a MAJOR bump at 1.0+; a MINOR may carry it pre-1.0, but it must be
flagged — see below) if it breaks **any** of these contracts, not only the Python API:

| Contract | Breaking change examples |
|---|---|
| **Python API** | Removing/renaming a public symbol; changing a signature, return type, or the exception type a caller catches |
| **On-chain artifact bytecode** | Changing covenant/script bytecode or a dMint contract such that a newly-built artifact's **address/SPK changes**, or it's incompatible with assumptions about existing on-chain state. *(The 0.8.0 `OP_SIZE` preimage-length pin was exactly this — it shifted the HTLC address + covenant SPKs; a protocol bump.)* |
| **Wire / serialization formats** | The `SwapRecord` JSON schema, the recovery-file format, the RSWP order frame, the Glyph CBOR envelope |
| **Security posture / safety defaults** | Weakening a fail-closed property or flipping a safety default — **even if the Python signature is unchanged.** *(See "the rule 0.9.0 violated".)* |

## Pre-1.0 reality

pyrxd is **0.x**: the API and on-chain formats are **not yet stable**.

- A **minor** (`0.N → 0.N+1`) **may** carry breaking-class changes. It **must** call them out (see below).
- A **patch** (`0.N.x → 0.N.x+1`) carries only backward-compatible fixes.
- Only the **latest published minor** receives security fixes — see [`SECURITY.md`](../SECURITY.md).
- At **1.0**, MAJOR/MINOR/PATCH take their full SemVer meaning: breaking-class changes require a MAJOR.

## The rule 0.9.0 violated (and the lesson)

0.9.0's CHANGELOG said _"no breaking API changes"_ while it turned `require_audit_cleared` /
`require_spv_sole_authority_cleared` from fail-closed gates into **advisory no-ops** — a real change to a
security-relevant default. By the table above that is **breaking-class**, even though no Python signature
changed. The lesson, now policy:

1. **A change to a safety property or a fail-closed default is breaking-class** and must be the headline
   of its CHANGELOG entry — never folded under "no breaking changes."
2. **Where it changes a runtime default, emit a one-time `DeprecationWarning`** (or a startup log for an
   operational gate) so a downstream that relied on the old behavior sees it in logs/CI, not in
   production. A silent behavioral reversal of a security gate is the least-surprise violation an SDK
   must avoid most.

## Deprecation process

To retire a public symbol or behavior:

1. **Keep it working for ≥ 1 minor** with a `DeprecationWarning` (`stacklevel=2`) that names the
   replacement.
2. **Document it:** a CHANGELOG **`Deprecated`** entry, plus a migration note in the
   [migration guides](how-to/migrate-0.4-to-0.5.md) when a caller must change code.
3. **Remove** no earlier than the next minor (pre-1.0) / the next MAJOR (1.0+).
4. **On-chain format changes** carry a protocol-version note (which on-chain state they're compatible
   with) — old artifacts on superseded bytecode are documented, not silently re-pointed
   (cf. the mainnet LWMA dMint deploy on pre-fix bytecode).

## What SemVer here does NOT promise

So consumers don't over-rely:

- The unaudited cross-chain swap stack's **safety against a hostile counterparty** — that's the external
  audit gate + the residual register, not a version promise.
- **Transitive dependency pins** — pyrxd is a library and intentionally does not pin its consumers'
  transitive graph (`SUPPLY-NOPIN`); pin in your own lockfile.
- The **exact bytes of an error message** or internal/underscored symbols.

## See also

- [`SECURITY.md`](../SECURITY.md) — supported versions + the safe-harbor / disclosure policy.
- [`security-audit-scope.md`](security-audit-scope.md) — the residual register breaking changes must keep honest.
- The [migration guides](how-to/migrate-0.4-to-0.5.md).
