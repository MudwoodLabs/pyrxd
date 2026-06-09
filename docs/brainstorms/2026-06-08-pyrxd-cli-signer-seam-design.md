# Design: key-custody for the pyrxd CLI (#8 agent, Ledger) — REVISED post-review

**Status:** draft / brainstorm, **revised after a divergent review panel**
(architecture-strategist · code-simplicity-reviewer · kieran-python ·
security-sentinel, each writing independently). Working space — references
private/sibling projects (rxdpy-signer, the Ledger app). Sanitize before
any public release.

**What changed in this revision (panel findings folded in):**
- **The central question moved.** The first draft assumed a `Signer` seam
  was needed. The panel showed that depends entirely on *what #8 is* —
  see §0. The minimal #8 needs **no seam**.
- **Factual correction.** The first draft claimed gravity/swap sign via
  `P2PKH().unlock(key)`. **False for gravity:** it hand-rolls the Radiant
  BIP143 preimage and signs via `coincurve` directly
  (`gravity/transactions.py:125-182`); the HTLC fee input uses a bare WIF
  (`gravity/htlc_spend.py:118-140`). Only the HD-wallet P2PKH path and
  `pyrxd.swap` go through the template. So a template-level seam does NOT
  unify "all signing," and leaves the real-money gravity/HTLC paths
  outside custody.
- **If a seam is built, the contract is tightened** (typed return,
  full-path KeyId, structured re-derivable request, prevout
  verification, set-then-sign sighash) — §3.
- **Security: not safe to build the out-of-process backend as first
  drafted** — §4. The default in-process signer is *not* a custody
  improvement; say so honestly.

---

## 0. The crux: what is #8, actually? (decide this first)

Issue #8 is filed as a **mnemonic re-entry UX** problem
(`docs/cli-security-backlog.md`): retyping the mnemonic on every command
is annoying and increases exposure. There are **three** distinct products
hiding under that, with very different security:

### Path A — seed-vending agent. NOT RECOMMENDED (convenience only).
`pyrxd agent unlock` holds the seed in a daemon; `_load_wallet` fetches
the seed/xprv back from it and signs in the CLI as today. One branch, no
seam.
- **Security: same as today or worse.** The socket becomes a
  *seed-vending machine* — anything that opens it gets the **whole
  seed**, not one signature, and there's **no confirmation possible**
  because the agent doesn't sign, it vends. Same-uid processes (a
  malicious pip dep, a plugin) pass `SO_PEERCRED` trivially → silent
  full-wallet drain. Plus the seed now sits resident in a long-lived
  process (bigger memory-scrape window) *and* still re-enters the CLI.
- Only narrow win: cuts mnemonic-*entry* exposure (shoulder-surf,
  clipboard, scrollback) to once per session.
- This is the `ssh-agent` anti-pattern (real agents never hand the key
  back). **Do not build this.**

### Path A′ — sign-on-behalf agent. RECOMMENDED near-term. NO generalized seam.
`pyrxd agent unlock` holds the wallet in the daemon (`SecretBytes`,
auto-lock). The daemon **signs on behalf** — the CLI sends an *unsigned*
tx + input coordinates; the agent re-derives the keys, verifies, signs,
and returns the **signed tx**. The key **never leaves the daemon**.
- **Security: a real improvement.** Reaching the socket no longer equals
  stealing the key — a same-uid attacker can at most *request* a
  signature, which the **interactive per-spend confirmation** gates.
- **Cost: moderate, not large.** The agent just wraps `HdWallet` and
  moves the `tx.sign()` step inside the daemon. The CLI becomes
  *watch-only* (builds txs from addresses/xpub, no keys) and defers
  signing. This is more than Path A's "one branch" (the CLI/agent split
  is real) but **far less than Path B** — it needs **none** of the
  generalized `Signer`/`KeyId`/`unlock_with_signer` machinery (§2–§3).
- **Mandatory hardening (because it signs):** the §4 requirements apply —
  prevout authenticity (C1), no blind-signing + confirmation (H1/H2),
  socket auth, memory hygiene, TOCTOU. These are inherent to *any*
  key-protecting agent, seam or not.

### Path B — pluggable `Signer` seam. LATER, Ledger-driven.
A′ generalized so the signing backend is swappable (agent, **Ledger**,
HSM). Adds the `Signer` Protocol + `KeyId` + template rewrite (§2–§3).
- **Cost: large.** Justified by **Ledger** (key in hardware), which is a
  separate, unscheduled goal — *not* by #8.

**Recommendation (panel-informed):** build **A′ now** — it's the version
that actually improves custody for #8, without the speculative seam.
Build the **Path B seam only when Ledger is scheduled**, and co-design it
against two real backends (the A′ agent + Ledger) rather than guessing.
Extracting a seam from two real implementations beats inventing it for
zero.

§4 below is the hardening A′ must adopt now. §2–§3 specify the Path B seam
**for when it's time**, so it isn't re-litigated.

---

## 1. Current signing paths (corrected)

There is no single interface every command signs through. There are
**three distinct shapes**, and a template-level seam only covers the
first two-and-a-bit:

1. **HD-wallet P2PKH** — `P2PKH().unlock(privkey)` →
   `privkey.sign(tx.preimage(i))` (`script/type.py:77-90`,
   `hd/wallet.py:763-789`). The raw `PrivateKey` lives in-process.
2. **`pyrxd.swap`** — also `P2PKH().unlock(key)` (the merged #123 work).
3. **gravity + HTLC** — **does NOT use the template.** Hand-rolls the
   preimage and signs via `coincurve`
   (`gravity/transactions.py:125-182`, `_sign_radiant_p2sh_input`);
   covenant/HTLC spends carry custom scriptSigs; the fee input signs a
   bare WIF (`gravity/htlc_spend.py:118-140`). **This is where real value
   moves** (the proven mainnet swaps).

Implication: the custody seam must be anchored at the **digest /
signing-request** level shared by (1)(2)(3), not the P2PKH-`Script`
level — otherwise it covers the easy half and leaves gravity/HTLC's keys
in-process while claiming "pluggable custody."

## 2. Where to cut the seam (altitude — the architect-vs-security reconciliation)

The two reviewers pushed opposite ways and **both are right**, which
pins the answer:

- **Architecture:** don't pass the live pyrxd `Transaction` object across
  a socket/device boundary — backends would have to link pyrxd's preimage
  code; a Ledger can't parse a Python object anyway. Push the cut *down*
  toward a digest.
- **Security:** don't pass a **bare digest** — that's blind signing; the
  backend can't verify prevout value/script (fee-theft, C1) or show the
  user what they sign (H1/H3). Push the cut *up* toward structured intent.

**Reconciliation — a structured, serializable, self-verifying signing
request** (neither a live object nor a bare digest):

```python
@dataclass(frozen=True)
class SigningRequest:
    raw_tx: bytes                 # canonical serialized tx (parseable by a device)
    input_index: int
    key_id: KeyId                 # full BIP32 path (§3)
    sighash: SIGHASH
    prevouts: list[PrevOut]       # value+script per input — but see C1:
                                  # the backend RE-VERIFIES these, never trusts them
```

The backend (agent/Ledger) re-derives the preimage *from the bytes it
will display*, independently confirms the prevouts (re-fetch by outpoint,
or require full source txs and check `txid`), and signs **that exact**
preimage in one atomic step (no display-then-resign TOCTOU, Security M2).
The in-process template path can keep computing `tx.preimage(i)` locally
and calling a thin `sign_digest` — the wire artifact only matters at the
process/device boundary.

## 3. The `Signer` contract (tightened per kieran + architecture)

```python
@dataclass(frozen=True, slots=True)
class KeyId:                       # full path — NOT a bare (change, index) tuple
    change: int
    index: int
    account: int = 0
    coin_type: int = 512
    def bip32_path(self) -> str: ...

@dataclass(frozen=True)
class InputSignature:              # typed — carries the sighash it committed to
    der: bytes                    # strict DER, low-s (matches PrivateKey.sign)
    pubkey: PublicKey             # returned WITH the sig (one call, can't desync)
    sighash: SIGHASH

@runtime_checkable
class Signer(Protocol):
    def sign(self, request: SigningRequest) -> InputSignature: ...
```

Tightening (all from the panel):
- **Typed return** `InputSignature(der, pubkey, sighash)` — not bare
  `bytes`. The template asserts `sig.sighash == expected` and assembles
  the scriptSig in one place. Pubkey returned *with* the sig so a backend
  can't sign with key A and report pubkey B (architect MINOR 7/8).
- **Full-path `KeyId` dataclass**, frozen+slots (hashable → cacheable).
  A bare `(change, index)` can't address gravity/imported keys and forces
  every backend to re-guess `m/44'/coin'/account'` (architect M3, kieran
  M2, security L2). Define it correctly *before* it enters the Protocol.
- **Set-then-sign sighash.** `from_hex` does NOT recover sighash (it's
  not a serialized field — `transaction_input.py:58-87` defaults it to
  `ALL_FORKID`). Pass sighash explicitly, *set* it on the input before
  preimage (like `RPuzzle.unlock`, `type.py:259`), and assert the backend
  signed under it. This is the exact footgun the #123 swap work already
  hit (kieran M3).
- **Wallet owns the signer.** Give `HdWallet` a `self._signer`
  (default `LocalSigner(self._xprv)`); don't thread `(signer, key_id)`
  through every method signature — match how `RefAuthenticityIndexer` /
  `FeeUtxoSource` are constructor-injected (architect M5).
- **Standardize on `PrivateKeyMaterial`,** not `keys.PrivateKey`, inside
  `LocalSigner` (zeroize per call, like `eth_wallet/htlc_leg.py:271-279`).
  Keep `P2PKH().unlock(PrivateKey)` as a thin deprecated shim; do **not**
  let `keys.PrivateKey` into the Protocol surface (architect M6).
- **No "expose the privkey for back-compat" escape hatch** (security M1).
- **Typed error taxonomy:** `SignerError(ValidationError)` /
  `SignerUnavailableError(NetworkError)` so the `_load_wallet` fallback
  ladder branches on type, not exception-string matching (kieran m6).
- **Ctor `isinstance` check** at each injection site (`runtime_checkable`
  only checks method names) — fail closed, name the missing method
  (kieran m1).

## 4. Security requirements for any sign-on-behalf agent (A′ AND Path B)

These apply the moment a daemon/device signs on your behalf — i.e. to
**A′ now**, and to Path B's agent/Ledger backends later
(security-sentinel — MUST adopt). They do NOT apply to Path A's
seed-vending model, which is why Path A is rejected: it has no signing
step to gate, so a same-uid attacker just takes the seed. The in-process
path (today, and Path B's `LocalSigner`) inherits the caller==wallet
trust model and is *not* itself a custody improvement (state plainly — M3):

- **C1 (critical) — prevout authenticity.** The preimage commits to each
  input's `satoshis` + `locking_script`, which today come from
  caller-supplied data (`transaction_input.py:32-34`,
  `hd/wallet.py:781-789`). A lying caller (claims a 100-RXD UTXO is 1 RXD)
  gets a valid tx that burns 99 RXD to fee. The backend MUST
  independently obtain/verify prevout value+script (re-fetch by outpoint
  or verify full source-tx `txid`), never trust the request's claim.
- **H1/H3 — no blind signing.** The backend MUST receive a structured tx
  it can fully parse and attribute (which outputs are change to its own
  derived keys vs external), and MUST refuse if it can't. No signing of
  bare 32-byte digests. A Ledger backend is a **gating spike**: confirm
  the device app parses Radiant's BIP143 incl. the ref-aware
  `hashOutputHashes` field (`transaction_preimage.py:66-92`) *before*
  `LedgerSigner` is more than a stub; until then it IS blind-signing.
- **H2 — same-uid is inside the trust boundary.** `SO_PEERCRED`
  uid==owner + `0700` socket dir are necessary but **not sufficient**: a
  same-uid process (compromised dep, malicious plugin) passes them. The
  real control for non-trivial amounts is **interactive per-spend
  confirmation** (show attributed outputs/total/fee, require a keypress).
- **Memory hygiene under failure (L1):** `mlock` the seed pages, disable
  core dumps, `PR_SET_DUMPABLE 0`, `SIGTERM`/`SIGINT` handlers that
  zeroize; document that `SIGKILL`/crash cannot be scrubbed.
- **sighash is security-relevant (L3):** treat anything other than the
  expected `ALL|FORKID` on a normal spend as requiring confirmation.

### Agent threat-model doc (issue #8 criterion #4) MUST contain
1. Socket auth: `0700` dir **and** `SO_PEERCRED` uid==owner; explicit
   admission same-uid processes can originate requests.
2. The real control: interactive per-spend confirmation with amount
   thresholds.
3. Prevout authenticity (C1).
4. Display==sign atomicity / TOCTOU single-buffer rule (M2).
5. Memory hygiene + the honest `SIGKILL` limit (L1).
6. Explicit non-goals: does not defend a user who blind-confirms; signs
   only structured re-derivable txs, never arbitrary digests.

## 5. Net effect on the open work (revised)

- **#8 (now):** build **Path A′** — sign-on-behalf agent (key never
  leaves the daemon), CLI goes watch-only and defers signing, with the §4
  hardening (prevout check, confirmation, socket auth, memory hygiene).
  No generalized seam. This is the version that actually improves custody.
  (Path A, seed-vending, is rejected — §0.)
- **Ledger / pluggable custody (later):** build **Path B** — the §3 seam +
  §4 hardening, co-designed against the A′ agent **and** Ledger together.
  This is where the seam earns its keep.
- **rxdpy-signer:** out of scope and intentionally unmentioned in the
  seam — it's a different SDK and a different altitude (intent/HTTP). The
  first draft's "two-altitude" framing was concept bloat (simplicity);
  reuse its *patterns* (sealed-at-rest, hash-chained audit, policy-in-PR)
  for the agent's at-rest story, nothing more.

## 6. Recommended sequencing

1. **Path A′ #8** as its own PR: daemon holds the wallet + signs on
   behalf; CLI watch-only build → defer sign → receive signed tx; socket
   (`0700` + `0600` + `SO_PEERCRED`), auto-lock, the §4 hardening
   (prevout verification, per-spend confirmation, mlock/no-coredump/
   `PR_SET_DUMPABLE`), and the issue-#8 threat-model doc. Ships the UX
   *and* a real custody gain.
2. **Decide Ledger.** If/when scheduled → Path B: land the §3 `Signer`
   seam as a zero-behavior-change refactor (LocalSigner default,
   byte-identical, two-pass-fee regression test), then add `AgentSigner`
   (sign-on-behalf, §4 hardening) and `LedgerSigner` (after the parsing
   spike) as additive backends.
3. Only then retrofit gravity/HTLC signing onto the seam (the hand-rolled
   `_sign_radiant_p2sh_input` calls `sign` on a digest it already
   computes — low-friction once the seam exists).
```
