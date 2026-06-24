# Radiant cross-implementation conformance vectors

Language-agnostic, versioned test vectors so independent Radiant implementations
(pyrxd, radiantjs, Photonic, …) can **differential-test against the same canonical bytes** rather than
each other's running code. Each file is plain JSON: load it, build the artifact from `params`, and
byte-compare against the expected hex.

## Suites

| File | Covers | Anchor |
|---|---|---|
| `dmint-v2-contract-vectors.json` | The V2 dMint **contract script** for given deploy params, across all 5 DAA modes (FIXED / LWMA / ASERT / EPOCH / SCHEDULE) | One vector is byte-anchored to the first **mainnet** V2 deploy (`source: mainnet:…`); the rest are reference vectors |

## Format (`dmint-v2-contract-vectors/1`)

```jsonc
{
  "schema": "radiant-dmint-v2-contract/1",
  "builder": "build_dmint_contract_script(DmintDeployParams(**params))",
  "vectors": [
    {
      "id": "v2-fixed-mainnet",
      "source": "mainnet:<deploy-reveal-txid>:vout0",   // or "reference"
      "params": { "contract_ref": {"txid": "<display-hex>", "vout": 1},
                  "token_ref":    {"txid": "<display-hex>", "vout": 0},
                  "max_height": 10, "reward": 1000, "difficulty": 1,
                  "algo": "SHA256D", "daa_mode": "FIXED", "target_time": 60,
                  "half_life": 3600, "height": 0, "last_time": 0,
                  "epoch_length": 2016, "max_adjustment_log2": 2, "schedule": [] },
      "contract_script_hex": "00d8…"
    }
  ]
}
```

`algo` / `daa_mode` are enum **names**; `contract_ref` / `token_ref` are `{txid (display byte order), vout}`.

## Authority & honesty

pyrxd is the **reference** producer here: its V2 builder is byte-matched to canonical Photonic and to the
mainnet FIXED deploy. `tests/test_dmint_conformance_vectors.py` re-derives every vector from `params` and
fails CI if the builder ever diverges from the published hex — so the JSON cannot silently rot. To
regenerate after an intentional builder change, rebuild each vector with `build_dmint_contract_script`
and bump the schema if the *format* changes (not just the bytes).

> Note: the mainnet **LWMA** deploy (`dea3beb9…`) is **not** an anchor — it predates the upstream
> int64-overflow fix (it lacks the `OP_0 OP_MAX` timeDelta floor), so the current builder correctly emits
> 2 bytes more. Only FIXED is mainnet-anchored; the other modes are reference vectors.
