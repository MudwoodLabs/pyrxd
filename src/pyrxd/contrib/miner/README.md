# pyrxd-miner

Parallel pure-Python SHA256d miner — the bundled reference
implementation of pyrxd's external-miner JSON protocol.

## Install

Ships with pyrxd >= 0.5.1. No extras needed.

```bash
pip install 'pyrxd>=0.5.1'
```

## Use

Two invocation paths.

**Via `mine_solution_external` (recommended):**

```python
import sys
from pyrxd.glyph.dmint import build_pow_preimage, mine_solution_external

pow_result = build_pow_preimage(txid_le, contract_ref, in_script, out_script)
result = mine_solution_external(
    preimage=pow_result.preimage,
    target=state.target,
    miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner"],
    nonce_width=4,
)
```

`mine_solution_external` re-verifies every nonce the miner returns
against pyrxd's internal SHA256d check — a buggy or malicious miner
can't ship a wrong nonce into your transaction.

**Via the `pyrxd-miner` console script:**

```bash
echo '{"preimage_hex":"...","target_hex":"7fffffffffffffff","nonce_width":4}' \
    | pyrxd-miner
```

Flags:

- `--workers N` — override `os.cpu_count()`.
- `--quiet` — suppress stderr progress on exhaustion.
- `--protocol-version` — print supported protocol version.
- `--help` — full usage.

## Protocol

See [docs/concepts/parallel-mining.md](../../../../docs/concepts/parallel-mining.md)
for the full wire-protocol spec, exit codes, and operational notes.

## API stability

`pyrxd.contrib.*` is **shipped but non-core**. pyrxd makes no semver
promises about the Python import surface; the wire protocol
(JSON-over-stdio, exit codes) IS pinned.

Programmatic consumers should treat the CLI as the API. Importing
`pyrxd.contrib.miner.parallel.mine` directly is allowed but the
function signature may change in a minor release; the CLI invocation
will not.
