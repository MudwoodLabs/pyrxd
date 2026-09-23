# sha256d-grind — the native SHA256d grinder

A small C program that grinds dMint proof of work and speaks pyrxd's
[external-miner protocol](../../../../../docs/concepts/parallel-mining.md#the-wire-protocol-v1),
so it drops in wherever `python -m pyrxd.contrib.miner` does. pyrxd ships the
source (`sha256d_grind.c`), not a binary; `pip install pyrxd` neither needs
nor builds it.

## Build

```bash
python -m pyrxd.contrib.miner.native --out ./sha256d-grind
```

That compiles with the machine's C compiler (`$CC`, else `cc`, `gcc` or
`clang`) using `-O2 -pthread`, runs the binary's `--selftest`, and deletes the
binary if the self-test fails. The equivalent by hand:

```bash
cc -O2 -pthread -o sha256d-grind "$(python -m pyrxd.contrib.miner.native --print-source)"
./sha256d-grind --selftest
```

It needs C11, POSIX threads and `unsigned __int128`: a 64-bit target with GCC
or Clang (Linux, macOS). The self-test prints which SHA-256 implementation it
will use on this CPU:

```text
selftest ok: impl=shani shani_available=1 threads=32
```

## Use

```bash
pyrxd glyph claim-dmint ... --miner-cmd ./sha256d-grind
```

```python
from pyrxd.glyph.dmint import mine_solution_external

result = mine_solution_external(preimage, target, miner_argv=["./sha256d-grind"], nonce_width=4, algo=state.algo)
```

`mine_solution_external` re-checks every nonce the grinder returns with
`verify_sha256d_solution` before returning it, as it does for any external
miner. The protocol carries no algorithm: pass the contract's `algo` and pyrxd
refuses BLAKE3 and K12 contracts before the grinder is started.

Options: `--workers N` (threads; default: the CPUs this process may run on),
`--quiet` (no progress frames or exhaustion message on stderr),
`--impl auto|portable|shani`, `--selftest`, `--protocol-version`, `--help`.
`--nonce-start`, `--nonce-count`, `--enumerate` and `--target96` exist for the
tests; `--help` describes them.

## What it computes

For each nonce `n` it computes `SHA256(SHA256(preimage || LE(n, nonce_width)))`
and reports `n` if the digest's first four bytes are zero and bytes 4..12, read
big-endian, are below `min(target, 2**63 - 1)` — `verify_sha256d_solution`'s
rule. It is faster than the Python miners because the 64-byte preimage is
exactly one SHA-256 block, compressed once per request, so each attempt costs
two compressions rather than three; both remaining blocks have fixed padding;
nothing is allocated per attempt; and on x86-64 CPUs with the SHA extensions
the compression uses them (chosen at run time with CPUID). Other CPUs use the
portable C compression.

## How it is checked

`tests/contrib/test_native_grinder.py` builds it with the helper above and
compares it with `hashlib` and `verify_sha256d_solution`: every digest over
nonce ranges (including the top of each nonce space), for both nonce widths
and both implementations; the exact set of hits over ranges of 131,849 nonces
against an exhaustive `hashlib` sweep, at 1, 3 and 8 threads; real
difficulty-1 solutions found at their exact nonce, with a range that stops one
nonce short reported exhausted; the strict `<` at `target == value`; the target
ceiling; the request parser against the Python one; and the path through
`mine_solution_external`.

## Speed

Measured 2026-09-23 on one machine, an Intel Core i9-14900K (24 cores, 32
threads, with the SHA extensions) that was also running a desktop session,
three runs each, with `scripts/bench_dmint_miners.py`:

| threads / workers | bundled Python miner | sha256d-grind |
|---|---|---|
| 32 | 25.3, 25.7, 25.4 M hash/s | 318.0, 312.9, 314.8 M hash/s |
| 4 | 5.7, 5.4, 6.8 M hash/s | 47.9, 48.0, 48.0 M hash/s |
| 1 | 1.5, 1.7, 1.7 M hash/s | 12.7, 12.6, 12.7 M hash/s |

Without the SHA extensions (`--impl portable`) the same machine measured
3.2 M hash/s on one thread and 43.2 M hash/s on 32 (one run each). Run
`scripts/bench_dmint_miners.py --grinder ./sha256d-grind` from a pyrxd checkout for your own
numbers.
