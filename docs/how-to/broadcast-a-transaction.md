# How to broadcast a transaction

You have a signed Radiant transaction (as raw bytes or a hex string) and
want to push it to the network. pyrxd does not ship a generic
`pyrxd broadcast` subcommand — the CLI surface is task-shaped (`pyrxd
glyph deploy-ft`, `pyrxd glyph transfer-ft`, etc.), and each task
broadcasts its own tx as the final step. For a tx you built yourself,
broadcast via the async `ElectrumXClient.broadcast(...)` API.

---

## Python: broadcast a signed tx via ElectrumXClient

`ElectrumXClient` is async-only. The client is a context manager —
opening it inside `async with` guarantees the WebSocket is closed on
exit and any in-flight RPC is cancelled.

```python
import asyncio

from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError

ELECTRUMX_URL = "wss://electrumx.radiant4people.com:50022/"


async def main(signed_tx_hex: str) -> None:
    raw_tx = bytes.fromhex(signed_tx_hex)
    async with ElectrumXClient([ELECTRUMX_URL]) as client:
        txid = await client.broadcast(raw_tx)
        print(f"Broadcast: {txid}")


asyncio.run(main("0100000001..."))
```

`broadcast()` accepts `bytes`/`bytearray` and validates them as
`RawTx` (must be > 64 bytes, the Merkle-forgery defense). It returns a
`Txid` on success. If you already have a `Transaction` object, pass
`tx.serialize()` rather than `tx.hex()` — same bytes, no round-trip
through hex. For the end-to-end "build + sign + broadcast" pattern see
[`examples/ft_transfer_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/ft_transfer_demo.py).

The URL must be `wss://` (TLS). Bare `ws://` is rejected at construction
time unless you pass `allow_insecure=True`; do that only for a local
regtest node.

---

## Handling broadcast errors

Every broadcast failure pyrxd can detect surfaces as
`pyrxd.security.errors.NetworkError`. The client deliberately does not
embed the server's raw error string in the exception message (that
string can include attacker-controlled bytes from the rejected tx).
Diagnose by the *symptom* on the chain, not the exception text.

```python
from pyrxd.security.errors import NetworkError

try:
    txid = await client.broadcast(raw_tx)
except NetworkError:
    # Inspect inputs against the chain to decide what went wrong.
    raise
```

The four rejections you will actually hit:

- **`bad-txns-inputs-missingorspent`** — one of your inputs is already
  spent (or never existed). Re-fetch UTXOs with
  `client.get_utxos(script_hash)` and rebuild the tx from the current
  set.
- **`txn-mempool-conflict`** — a different tx that spends the same
  input is already in the mempool. Either wait for it to confirm and
  rebuild from the resulting UTXO set, or RBF-replace it (Radiant
  inherits BCH's first-seen policy — RBF is not guaranteed; in practice
  you wait).
- **`min relay fee not met`** — the fee per byte is below the node's
  relay floor. Increase `fee_rate` (the examples use `10000` photons/
  byte for transfers) and rebuild. The fee field is the *total* fee,
  derived from `fee_rate * tx_byte_length`.
- **`mandatory-script-verify-flag-failed`** — a script in your tx
  failed verification. For a V1 dMint mint specifically, this is the
  symptom of the scriptSig divergence bug fixed in 0.5.0; see
  [V1 dMint mint scriptSig divergence](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md)
  for the root cause and the migration steps. For non-dMint txs it
  means a signature or hashlock is wrong; re-check the sighash type
  (Radiant uses BIP143 variants, see `pyrxd.security.types.SighashFlag`),
  the signed digest, and any ref-aware preimage pieces.

The client surfaces all four as a generic `NetworkError`. To see the
underlying ElectrumX response code, log at `DEBUG` level on the
`pyrxd.network.electrumx` logger — the reader loop logs RPC errors
before wrapping them.

---

## Verify the tx landed

`ElectrumXClient.get_transaction_verbose(txid)` returns the server's
JSON-decoded view of the tx, including a `confirmations` field. Poll
that until it's >= 1 (or however many confirmations your use case
demands):

```python
import asyncio

from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Txid


async def wait_for_confirm(
    client: ElectrumXClient,
    txid: str,
    *,
    min_confirmations: int = 1,
    timeout_s: float = 1800.0,
    interval_s: float = 10.0,
) -> None:
    deadline = asyncio.get_event_loop().time() + timeout_s
    while True:
        try:
            info = await client.get_transaction_verbose(Txid(txid))
            if int(info.get("confirmations", 0)) >= min_confirmations:
                return
        except NetworkError:
            # Tx may not be visible to this server yet — keep polling.
            pass
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError(f"{txid} did not confirm within {timeout_s:.0f}s")
        await asyncio.sleep(interval_s)
```

A transient `NetworkError` while polling usually means the server
hasn't seen the tx yet (mempool replication lag) — keep going. A
*persistent* failure across the full timeout means the tx never landed;
diagnose with the error table above. As a sanity check, the tx is also
visible to any Radiant block explorer once it confirms.

---

## References

- [`pyrxd.network.electrumx.ElectrumXClient`](https://github.com/MudwoodLabs/pyrxd/blob/main/src/pyrxd/network/electrumx.py) — the broadcast and polling API
- [`examples/ft_transfer_demo.py`](https://github.com/MudwoodLabs/pyrxd/tree/main/examples/ft_transfer_demo.py) — full build + sign + broadcast pattern
- [V1 dMint mint scriptSig divergence](../solutions/logic-errors/dmint-v1-mint-scriptsig-divergence.md) — the `mandatory-script-verify-flag-failed` symptom for V1 mints
