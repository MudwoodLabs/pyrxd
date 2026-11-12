"""``pyrxd swap build-eth-refund`` — sign the taker's ETH counter-leg refund and PRINT it (#818).

**This command never broadcasts.** It signs ``refund()`` on the swap's HTLC contract with the
refundee's key and prints the raw transaction and its hash; the operator inspects it and sends it
from a node of their choosing (``cast publish``, or ``eth_sendRawTransaction`` on any RPC). That is
the posture of the rest of the cold toolkit (:mod:`pyrxd.cli.swap_recovery_cmds`), and it keeps this
command outside the external swap audit gate the same way.

Why it exists: when a resume of an ETH swap is refused (past the ETH deadline, or the recorded
inputs no longer satisfy the ``t_rxd`` bounds), the runner tells the operator to let the swap time
out and refund. ``build-refund`` covers the Radiant covenant; nothing covered the ETH leg, so an
operator had to write code against :class:`~pyrxd.eth_wallet.htlc_leg.EthHtlcContractLeg` at the
moment they could least afford to.

How it stays honest
-------------------
* The contract comes from the durable swap record the runner wrote beside the recovery file
  (``<swap-file>.swaprec.json``), never from a flag: its ``counterchain_locator`` is the contract
  and its negotiated terms. The record must be for the same hashlock and chain id as the recovery
  file, and must not be a maker's.
* Before anything is signed, the contract at that address must be EXACTLY the runtime those terms
  imply and its getters must return them
  (:meth:`~pyrxd.eth_wallet.htlc_leg.EthHtlcContractLeg.check_refund_target`), and it must not be
  settled. The chain id is checked on every endpoint, and the leg signs only for that chain.
* The refund itself is built by the leg's own :meth:`refund`, so every refusal it makes still
  applies here: not yet mature (read as the MIN head across endpoints), a key the token contract
  would refuse (``NotRefunder``), an empty token contract, an estimate above the gas ceiling, a
  sender who cannot cover the fee, and the ``eth_call`` preflight. Only the last step differs: the
  rpc handed to the leg keeps the signed bytes instead of sending them (:class:`_SignOnlyRpc`).
* A refund already on the record (the coordinator's, design §3.4) is read first. If it is mined or
  still pending, nothing new is signed: a second refund at a fresh nonce could only revert.

The record is not written. The coordinator reads the chain first, so its next
``reconcile_counter_leg`` or ``mutual_refund`` sees the contract refunded at the finalized block
and moves the record (:meth:`~pyrxd.gravity.swap_coordinator.SwapCoordinator._apply_counter_disposition`).
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click

from ..security.errors import ValidationError
from .context import CliContext
from .errors import UserError
from .format import emit, sanitize_terminal

__all__ = ["ColdEthRefund", "build_cold_eth_refund", "swap_build_eth_refund_cmd"]

#: The environment variable that may carry the refund key (hex), when no file is given.
KEY_ENV = "PYRXD_ETH_REFUND_KEY"

_NEVER_BROADCAST = (
    "This command NEVER broadcasts. Check the contract, the sender and the fee above, then send the "
    "raw transaction yourself (for example `cast publish --rpc-url <url> <raw>`). It is valid only at "
    "the nonce shown: if this key sends any other transaction first, build a new one."
)


class _SignOnlyRpc:
    """The rpc the leg is given here: every read goes to the real endpoint(s), nothing is sent.

    :meth:`send_raw` keeps the signed bytes and answers with their own hash, which is what the leg's
    ``_sign_and_send`` checks a node's answer against, so the leg's code path is unchanged up to the
    broadcast. It accepts ONE transaction: a second would mean the leg signed something this command
    did not expect, and it is refused rather than kept.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.signed_raw: bytes | None = None
        self.signed_tx: dict[str, Any] | None = None

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def preflight(self, tx: dict[str, Any]) -> None:
        await self._inner.preflight(tx)
        self.signed_tx = dict(tx)

    async def send_raw(self, raw_tx: bytes) -> str:
        from eth_utils import keccak

        if self.signed_raw is not None:
            raise ValidationError("refusing a second transaction: this command signs exactly one refund")
        self.signed_raw = bytes(raw_tx)
        return "0x" + keccak(self.signed_raw).hex()

    async def wait_receipt(self, *_: Any, **__: Any) -> dict[str, Any]:
        raise ValidationError("this command never broadcasts, so it has no receipt to wait for")


@dataclass(frozen=True)
class ColdEthRefund:
    """A signed, unsent refund of the ETH counter leg, and what it was checked against."""

    chain_id: int
    contract_address: str
    asset: str
    contract_balance: int
    refundee: str
    sender: str
    timeout_unix: int
    chain_time_unix: int
    nonce: int
    gas_limit: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    tx_hash: str
    raw_hex: str
    endpoints: int
    earlier_refund: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "eth_counter_leg_refund",
            "broadcast": False,
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "asset": self.asset,
            "contract_balance": self.contract_balance,
            "refundee": self.refundee,
            "sender": self.sender,
            "timeout_unix": self.timeout_unix,
            "chain_time_unix": self.chain_time_unix,
            "nonce": self.nonce,
            "gas_limit": self.gas_limit,
            "max_fee_per_gas": self.max_fee_per_gas,
            "max_priority_fee_per_gas": self.max_priority_fee_per_gas,
            "max_gas_cost_wei": self.gas_limit * self.max_fee_per_gas,
            "tx_hash": self.tx_hash,
            "raw_hex": self.raw_hex,
            "endpoints": self.endpoints,
            "earlier_refund": self.earlier_refund,
        }


def _iso(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_eth_locator(record_path: Path, facts: Any) -> tuple[Any, Any]:
    """The swap record at *record_path* and its ETH locator, checked against the recovery file's *facts*.

    Raises :class:`ValidationError` for a record that is missing, unreadable, for another swap or
    chain, written by the maker, or that holds no ETH locator.
    """
    from ..eth_wallet.locator import EthHtlcLocator
    from ..gravity.record_sink import JsonFileRecordSink
    from ..gravity.swap_state import RecordRole

    if not record_path.is_file():
        raise ValidationError(
            f"no swap record at {record_path}. scripts/eth_swap_run.py writes it beside the recovery file as "
            "<swap-file>.swaprec.json; pass --record if it is elsewhere"
        )
    record = JsonFileRecordSink(record_path).load_record()
    if record is None:  # pragma: no cover - is_file() was true, so load_record returns a record or raises
        raise ValidationError(f"the swap record at {record_path} is empty")
    if record.terms.hashlock.hex() != str(facts.hashlock_hex).lower():
        raise ValidationError(
            f"the swap record at {record_path} is for another swap: its hashlock is "
            f"{record.terms.hashlock.hex()[:16]}…, the recovery file's is {str(facts.hashlock_hex)[:16]}…"
        )
    if record.role is RecordRole.MAKER:
        raise ValidationError(
            "this swap record was written by the MAKER. The ETH counter leg is the taker's to refund (its refund "
            "pays the taker); the maker's own recovery is the covenant refund, `pyrxd swap build-refund`"
        )
    locator = record.counterchain_locator
    if not isinstance(locator, EthHtlcLocator):
        what = "no counter-leg locator" if locator is None else f"a {type(locator).__name__}"
        raise ValidationError(
            f"the swap record holds {what}, not a funded ETH HTLC, so there is no contract to refund. If the "
            "deploy was interrupted, its address is the record's pending deploy; resume the fund first"
        )
    if locator.hashlock_bytes != record.terms.hashlock:
        raise ValidationError("the record's ETH locator names another hashlock than its own terms; refusing it")
    if facts.eth_refund_to is not None and str(facts.eth_refund_to).lower() != str(locator.refundee).lower():
        raise ValidationError(
            f"the record's ETH contract refunds {locator.refundee}, the recovery file says the refundee is "
            f"{facts.eth_refund_to}; refusing to sign for either until they agree"
        )
    if facts.eth_timeout_unix_s is not None and int(facts.eth_timeout_unix_s) != int(locator.timeout):
        raise ValidationError(
            f"the record's ETH contract times out at unix {locator.timeout}, the recovery file says "
            f"{facts.eth_timeout_unix_s}; refusing to sign for either until they agree"
        )
    if facts.eth_chain_id is not None and locator.chain_id != facts.eth_chain_id:
        raise ValidationError(
            f"the record's ETH contract is on chain {locator.chain_id}, the recovery file says chain "
            f"{facts.eth_chain_id}; refusing to sign for either until they agree"
        )
    return record, locator


def parse_eth_key(text: str) -> Any:
    """A secp256k1 key from 64 hex characters (``0x`` optional). The text is never echoed back."""
    from ..security.secrets import PrivateKeyMaterial

    raw = text.strip().removeprefix("0x").removeprefix("0X")
    if len(raw) != 64:
        raise ValidationError("the ETH key must be 32 bytes written as 64 hex characters")
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise ValidationError("the ETH key is not hex") from None
    try:
        return PrivateKeyMaterial(key)
    except Exception:
        raise ValidationError("the ETH key is not a valid secp256k1 private key") from None


def is_value_bearing(chain_id: int) -> bool:
    """True unless one endpoint may decide on this chain: anvil's 31337 or a registry testnet.

    The swap coordinator's rule (``SwapCoordinator._single_source_may_decide``), reused so the two
    cannot drift. A chain id the registry does not know counts as value-bearing:
    ``scripts/eth_swap_two_host.py`` and library callers accept chains outside the registry (BSC and
    Polygon are left out of it on purpose).
    """
    from ..gravity.swap_coordinator import SwapCoordinator

    return not SwapCoordinator._single_source_may_decide(int(chain_id))


def _token_for(locator: Any) -> Any:
    """The :class:`Erc20Token` a token locator is denominated in.

    The pinned registry entry when there is one. A swap on a value-bearing chain can only have used a
    pinned token, so an unpinned one there is refused. On a test chain (a registry testnet, or
    anvil's 31337; see :func:`is_value_bearing`), an unpinned address is used as it stands: the refund reads only the
    token's address (its balance, and the ``token`` immutable the exact runtime check binds).
    """
    from ..eth_wallet.tokens import Erc20Token, token_by_address

    try:
        return token_by_address(locator.token_address, locator.chain_id)
    except ValidationError:
        if is_value_bearing(locator.chain_id):
            raise
        return Erc20Token("UNPINNED", locator.token_address, 0, locator.chain_id, has_blacklist=False)


def _leg_for(locator: Any, *, rpc: Any, key: Any, artifact: dict[str, Any]) -> Any:
    from ..eth_wallet.erc20_leg import Erc20HtlcLeg
    from ..eth_wallet.htlc_leg import EthHtlcContractLeg
    from ..eth_wallet.locator import Erc20HtlcLocator

    names = set((artifact.get("immutable_names") or {}).values())
    if isinstance(locator, Erc20HtlcLocator):
        if "token" not in names:
            raise ValidationError(
                "the swap's counter leg is an ERC-20 HTLC, but --artifact is the native EthHtlc artifact; "
                "pass the Erc20Htlc artifact the contract was deployed from"
            )
        return Erc20HtlcLeg(
            token=_token_for(locator), rpc=rpc, signing_key=key, chain_id=locator.chain_id, artifact=artifact
        )
    if "token" in names:
        raise ValidationError(
            "the swap's counter leg is a native-ETH HTLC, but --artifact is the Erc20Htlc artifact; pass the "
            "EthHtlc artifact the contract was deployed from"
        )
    return EthHtlcContractLeg(rpc=rpc, signing_key=key, chain_id=locator.chain_id, artifact=artifact)


#: What a refund already on the record means for signing another (design §3.4). ``None``: sign.
_EARLIER_REFUND_BLOCKS = {
    "mined": "is mined. Wait for it to finalize; `pyrxd swap status --check-chain` shows the contract refunded",
    "pending": (
        "is still pending at the node. A second refund at a new nonce could only revert once it mines; wait, or "
        "replace it from the wallet that holds this key"
    ),
    "nonce_gap": (
        "is queued behind a missing lower-nonce transaction of this key. Send or replace that transaction first; "
        "the refund then mines on its own"
    ),
}


#: ``refund()`` takes no arguments in both artifacts, so its calldata is exactly the selector.
_REFUND_SELECTOR = bytes.fromhex("590e1ae3")


#: The signed ``maxFeePerGas`` may be at most this many times the highest that an endpoint other than
#: the one the leg built with suggests, and no lower than the lowest base fee they report. The tip is
#: not checked on its own: EIP-1559 caps it at ``maxFeePerGas``, and tip oracles differ (some report 0). The leg reads its fees from one endpoint (``MultiSourceEthRpc.fee_fields`` is
#: primary-only), so this is the check that a lying first endpoint did not set them.
_FEE_TOLERANCE = 2


async def _assert_every_endpoint_agrees_to_send(rpc: Any, sender: str, tx: dict[str, Any]) -> None:
    """Refuse unless every endpoint says this key has nothing in flight at the signed nonce, and no
    endpoint but the first suggests much lower fees than were signed.

    The leg builds from ONE endpoint (the nonce, the fees and its read of a recorded refund are the
    primary's; ``multi_rpc.py``, "deliberately single-source"). A lying first endpoint could otherwise
    set a tip near the key's balance, sign at the nonce of a payment still pending (replacing it), or
    read a pending recorded refund as gone. Requiring ``pending == latest == nonce`` on every endpoint
    also covers this command's own refund, printed and sent by an earlier run but not yet mined.
    """
    sources = list(getattr(rpc, "sources", None) or [rpc])
    nonce = int(tx["nonce"])
    for i, src in enumerate(sources):
        pending = int(await src.get_transaction_count(sender, "pending"))
        latest = int(await src.get_transaction_count(sender, "latest"))
        if not (pending == latest == nonce):
            raise ValidationError(
                f"endpoint {i + 1} of {len(sources)} reads this key's nonce as {latest} mined, {pending} with "
                f"pending, and the refund was built at nonce {nonce}. Either a transaction of this key is "
                "still in flight (wait for it, or for an earlier refund this command printed, to mine or drop, or "
                "replace that nonce from the wallet that holds this key) or the endpoints disagree. Nothing is "
                "printed"
            )
    if len(sources) < 2:
        return
    others = [await src.fee_fields() for src in sources[1:]]
    signed_max = int(tx["maxFeePerGas"])
    ceiling = _FEE_TOLERANCE * max(int(o["maxFeePerGas"]) for o in others)
    if signed_max > ceiling:
        raise ValidationError(
            f"the refund was signed with maxFeePerGas {signed_max} wei, more than {_FEE_TOLERANCE}x the highest "
            f"the other endpoints suggest ({ceiling // _FEE_TOLERANCE} wei). The first --eth-rpc-url sets the "
            "fees; put another endpoint first, or check the first one. Nothing is printed"
        )
    # ``fee_fields`` is ``2 * base + tip`` (rpc.py), so each endpoint's base fee is recoverable from it.
    floor = min(
        (int(o["maxFeePerGas"]) - int(o["maxPriorityFeePerGas"])) // 2 for o in others
    )  # floor-is-deliberate: the lowest base any other endpoint reports; refusing only below it
    if signed_max < floor:
        raise ValidationError(
            f"the refund was signed with maxFeePerGas {signed_max} wei, below the base fee every other endpoint "
            f"reports (at least {floor} wei), so it could not mine and would hold this key's nonce. The first "
            "--eth-rpc-url sets the fees; put another endpoint first, or check the first one. Nothing is printed"
        )


def _assert_signed_matches(raw: bytes, tx: dict[str, Any], *, chain_id: int, to: str) -> None:
    """Refuse unless the signed bytes carry the fields this command prints.

    The printed nonce, gas and fees come from the transaction the leg preflighted; decoding the signed
    bytes keeps a later change inside ``refund()`` from showing the operator one transaction and
    handing them another.
    """
    from eth_account.typed_transactions import TypedTransaction
    from hexbytes import HexBytes

    try:
        signed = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"the signed refund is not an EIP-1559 transaction ({exc}); nothing is printed") from exc
    if signed.get("type") != 2:
        raise ValidationError(
            f"the signed refund is a type {signed.get('type')} transaction, not EIP-1559; nothing is printed"
        )
    want: dict[str, Any] = {
        "type": 2,
        "value": 0,
        "data": "0x" + _REFUND_SELECTOR.hex(),
        "chainId": int(chain_id),
        "to": str(to).lower(),
        "nonce": int(tx["nonce"]),
        "gas": int(tx["gas"]),
        "maxFeePerGas": int(tx["maxFeePerGas"]),
        "maxPriorityFeePerGas": int(tx["maxPriorityFeePerGas"]),
    }
    got: dict[str, Any] = {k: int(signed[k]) for k in want if k not in ("to", "data")}
    got["to"] = "0x" + bytes(signed["to"]).hex()
    got["data"] = "0x" + bytes(signed["data"]).hex()
    if got != want:
        diff = sorted(k for k in want if got[k] != want[k])
        raise ValidationError(
            f"the signed refund does not match the transaction checked before signing ({', '.join(diff)}); "
            "nothing is printed"
        )


def _resolve_key_source(eth_key_file: str | None) -> str | None:
    """The refund key from ``--eth-key-file`` (guarded read) or ``KEY_ENV``, in that order.

    Same precedence as :func:`~pyrxd.gravity.watch.cli_secrets.resolve_secret` with no inline flag,
    with errors that name the refund key; the file goes through ``read_secret_file`` only (no symlink,
    FIFO, unbounded or non-0600 read), and the env var is consulted only when no file was given.
    """
    import os

    from ..gravity.watch.cli_secrets import read_secret_file

    if eth_key_file:
        value = read_secret_file(eth_key_file, label="--eth-key-file").strip()
        if not value:
            raise ValidationError(
                f"--eth-key-file {eth_key_file} is empty; write the refund key to it, or omit the flag"
            )
        return value
    if KEY_ENV in os.environ:
        raw = os.environ[KEY_ENV]
        if not raw.strip():
            raise ValidationError(f"{KEY_ENV} is set but empty; set the refund key, or unset {KEY_ENV}")
        return raw
    return None


async def build_cold_eth_refund(
    *, record: Any, locator: Any, rpc: Any, key: Any, artifact: dict[str, Any]
) -> ColdEthRefund:
    """Check the contract, then sign the refund through the leg without sending it.

    *rpc* is an :class:`~pyrxd.eth_wallet.rpc.EthRpc` or a
    :class:`~pyrxd.eth_wallet.multi_rpc.MultiSourceEthRpc` pinned to ``locator.chain_id``. Raises
    :class:`ValidationError` for every refusal (with nothing signed), :class:`NetworkError` for a read
    that failed.
    """
    from ..eth_wallet.erc20 import balance_of
    from ..eth_wallet.erc20_leg import Erc20HtlcLeg
    from ..eth_wallet.keys import derive_address

    sign_only = _SignOnlyRpc(rpc)
    leg = _leg_for(locator, rpc=sign_only, key=key, artifact=artifact)
    if await leg.check_refund_target(locator):
        raise ValidationError(
            f"the HTLC at {locator.contract_address} is already SETTLED: it was claimed or refunded, and refund() "
            "would revert. Nothing was signed. Run `pyrxd swap status --check-chain` to see which: if it was "
            "CLAIMED, p is public and the covenant claim is due (`pyrxd swap recover-preimage`, then `build-claim`)"
        )
    now = int(await sign_only.latest_block_timestamp_min())
    if now < int(locator.timeout):
        raise ValidationError(
            f"the refund is not open yet: refund() opens at unix {locator.timeout} ({_iso(int(locator.timeout))}) "
            f"and the chain's head is at {now} ({int(locator.timeout) - now}s to go, read as the lowest head "
            "across endpoints). Nothing was signed; run this again after that time"
        )
    earlier: dict[str, Any] | None = None
    if record.counter_refund_tx_hash is not None and record.counter_refund_nonce is not None:
        progress = await leg.refund_progress(
            record.counter_refund_tx_hash,
            record.counter_refund_nonce,
            earlier=tuple(record.counter_refund_replaced_tx_hashes),
        )
        earlier = {
            "tx_hash": getattr(progress, "tx_hash", None) or record.counter_refund_tx_hash,
            "nonce": record.counter_refund_nonce,
            "progress": progress.kind,
        }
        block = _EARLIER_REFUND_BLOCKS.get(progress.kind)
        if block is not None:
            raise ValidationError(
                f"the swap record already holds a refund of this contract, {earlier['tx_hash']} at nonce "
                f"{earlier['nonce']}, and it {block}. Nothing was signed"
            )
    if isinstance(leg, Erc20HtlcLeg):
        balance = int(await balance_of(sign_only, leg.token, locator.contract_address))
        asset = f"{leg.token.symbol} {leg.token.address} (base units)"
    else:
        balance = int(await sign_only.get_balance(locator.contract_address))
        asset = "ETH (wei)"
    tx_hash = await leg.refund(locator)
    raw, tx = sign_only.signed_raw, sign_only.signed_tx
    if raw is None or tx is None:  # pragma: no cover - refund() returns only after send_raw
        raise ValidationError("the leg returned without signing a refund; nothing was signed")
    _assert_signed_matches(raw, tx, chain_id=locator.chain_id, to=locator.contract_address)
    await _assert_every_endpoint_agrees_to_send(rpc, derive_address(key), tx)
    return ColdEthRefund(
        chain_id=locator.chain_id,
        contract_address=locator.contract_address,
        asset=asset,
        contract_balance=balance,
        refundee=locator.refundee,
        sender=derive_address(key),
        timeout_unix=int(locator.timeout),
        chain_time_unix=now,
        nonce=int(tx["nonce"]),
        gas_limit=int(tx["gas"]),
        max_fee_per_gas=int(tx["maxFeePerGas"]),
        max_priority_fee_per_gas=int(tx["maxPriorityFeePerGas"]),
        tx_hash=tx_hash,
        raw_hex="0x" + raw.hex(),
        endpoints=len(getattr(rpc, "sources", None) or [rpc]),
        earlier_refund=earlier,
    )


def _lines(r: ColdEthRefund) -> list[str]:
    lines = [
        "ETH counter-leg refund (signed, NOT broadcast)",
        f"  chain id      : {r.chain_id}",
        f"  contract      : {r.contract_address}",
        f"  holds         : at least {r.contract_balance} {r.asset} (lowest across endpoints)",
        f"  pays          : {r.refundee} (the contract's refundee, fixed at deploy)",
        f"  sender        : {r.sender}",
        f"  refund opened : unix {r.timeout_unix} ({_iso(r.timeout_unix)}); chain head {r.chain_time_unix}",
        f"  nonce         : {r.nonce}",
        f"  gas limit     : {r.gas_limit}",
        f"  max fee       : {r.max_fee_per_gas} wei/gas (tip {r.max_priority_fee_per_gas}); "
        f"at most {r.gas_limit * r.max_fee_per_gas} wei",
        f"  tx hash       : {r.tx_hash}",
        f"  raw           : {r.raw_hex}",
    ]
    if r.endpoints == 1:
        lines.append(
            "  ⚠ Read from ONE endpoint: the contract checks, the nonce and the fees are its word only. Pass "
            "--eth-rpc-url more than once (distinct operators): the contract checks and the nonce must then agree "
            "on every endpoint, and the fees are checked against the others' suggestions."
        )
    if r.earlier_refund is not None:
        lines.append(
            f"  note: the record's earlier refund {r.earlier_refund['tx_hash']} (nonce {r.earlier_refund['nonce']}) "
            f"reads {r.earlier_refund['progress']}; it did not refund the contract, so this one replaces it."
        )
    lines.append(
        "  The swap record is not changed. Once this refund is final, the runner's next "
        "reconcile_counter_leg or mutual_refund reads it from the chain."
    )
    lines.append(_NEVER_BROADCAST)
    return lines


def _open_rpc(urls: tuple[str, ...], chain_id: int, *, single_endpoint: bool = False) -> Any:
    """One RPC over every URL. On a value-bearing chain one URL is refused unless ``single_endpoint``.

    With one endpoint, its word alone decides whether the contract is still unsettled. A lying one
    cannot redirect value (the contract fixes the refundee), but it can hide a claim, so the operator
    signs a refund that reverts and misses that the secret is public and their own claim is due.
    """
    from ..eth_wallet.multi_rpc import MultiSourceEthRpc
    from ..eth_wallet.rpc import EthRpc

    if len(urls) == 1 and not single_endpoint and is_value_bearing(chain_id):
        raise ValidationError(
            f"one --eth-rpc-url on value-bearing chain {chain_id}: pass it again with an endpoint from a "
            "different operator, so the contract checks need their agreement, or pass --single-endpoint to "
            "accept one endpoint's word"
        )

    sources = [EthRpc(u, expected_chain_id=chain_id) for u in urls]
    return sources[0] if len(sources) == 1 else MultiSourceEthRpc(sources)


@click.command(name="build-eth-refund")
@click.option(
    "--swap-file",
    "swap_file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="The recovery JSON scripts/eth_swap_run.py wrote (its --keys-out).",
)
@click.option(
    "--record",
    "record_path",
    default=None,
    type=click.Path(dir_okay=False, path_type=Path),
    help="The swap record. Default: <swap-file>.swaprec.json, where the runner writes it.",
)
@click.option(
    "--eth-rpc-url",
    "eth_rpc_urls",
    multiple=True,
    required=True,
    help="Ethereum JSON-RPC URL on the swap's chain. Repeat it (distinct operators): the contract checks and "
    "the key's nonce must agree on every endpoint, and the fees, which the first one sets, are checked "
    "against the others.",
)
@click.option(
    "--artifact",
    "artifact_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="The EthHtlc or Erc20Htlc artifact JSON the contract was deployed from (the runner's --eth-artifact "
    "or --erc20-artifact).",
)
@click.option(
    "--eth-key-file",
    default=None,
    help=f"File holding the refund key as hex (mode 0600, owner-only). Else ${KEY_ENV}, else the "
    "swap file's eth_key_hex.",
)
@click.option(
    "--single-endpoint",
    is_flag=True,
    default=False,
    help="Allow one --eth-rpc-url on a value-bearing chain (refused by default: one endpoint could hide a "
    "claim of the contract). Test chains accept one without it.",
)
@click.pass_obj
def swap_build_eth_refund_cmd(
    ctx: CliContext,
    swap_file: Path,
    record_path: Path | None,
    eth_rpc_urls: tuple[str, ...],
    artifact_path: Path,
    eth_key_file: str | None,
    single_endpoint: bool,
) -> None:
    """Sign the TAKER's refund of the ETH counter-leg HTLC and PRINT it. Never broadcasts.

    For a swap whose resume was refused: once the contract's timeout has passed, this signs
    refund() and prints the raw transaction for you to send. The contract and its terms come from
    the swap record, and the contract on chain must match them exactly before anything is signed.
    """
    from ..eth_wallet.htlc_leg import load_artifact
    from .swap_recovery import load_recovery_json, redact_endpoint_secrets
    from .swap_recovery_cmds import _load, _run

    facts, _extras = _load(swap_file)
    if facts.counter_chain != "eth":
        raise UserError(
            "this swap's counter leg is not on Ethereum",
            fix="build-eth-refund refunds an ETH or ERC-20 counter leg only",
        )
    record_file = record_path if record_path is not None else Path(str(swap_file) + ".swaprec.json")
    try:
        record, locator = load_eth_locator(record_file, facts)
        artifact = load_artifact(artifact_path)
        secret = _resolve_key_source(eth_key_file)
        if not secret:
            secret = load_recovery_json(swap_file).get("eth_key_hex") or None
        if not secret:
            raise ValidationError(
                f"no refund key: pass --eth-key-file PATH (mode 0600) or set {KEY_ENV}; the swap file holds no "
                "eth_key_hex"
            )
        key = parse_eth_key(str(secret))
        rpc = _open_rpc(eth_rpc_urls, locator.chain_id, single_endpoint=single_endpoint)
    except (ValidationError, ValueError, OSError) as exc:
        raise UserError(
            "could not prepare the ETH refund",
            cause=sanitize_terminal(redact_endpoint_secrets(str(exc), list(eth_rpc_urls)), max_len=500),
            fix="nothing was signed or broadcast — correct the input above and re-run",
        ) from exc

    async def _go() -> ColdEthRefund:
        try:
            return await build_cold_eth_refund(record=record, locator=locator, rpc=rpc, key=key, artifact=artifact)
        finally:
            close = getattr(rpc, "close", None)
            if close is not None:
                await close()

    from web3.exceptions import Web3Exception

    from .errors import NetworkBoundaryError

    try:
        refund = _run(_go(), url=eth_rpc_urls[0], scrub=tuple(eth_rpc_urls))
    except NetworkBoundaryError as exc:
        if "endpoints disagree (" not in str(exc.__cause__):
            raise
        raise NetworkBoundaryError(
            "the endpoints disagree",
            cause=sanitize_terminal(redact_endpoint_secrets(str(exc.__cause__), list(eth_rpc_urls)), max_len=500),
            fix="one endpoint is lying or lagging and there is no telling which from here: retry once they "
            "catch up, or replace one with an endpoint from another operator. Nothing was signed or broadcast",
        ) from exc
    except Web3Exception as exc:
        # A JSON-RPC error answer (an ``error`` object) to a read the leg does not wrap as NetworkError.
        raise NetworkBoundaryError(
            "a chain read returned an error",
            cause=sanitize_terminal(
                redact_endpoint_secrets(f"{type(exc).__name__}: {exc}", list(eth_rpc_urls)), max_len=300
            ),
            fix="check the endpoint, or use another; nothing was signed or broadcast",
        ) from exc
    except ValidationError as exc:
        raise UserError(
            "refused to sign the ETH refund",
            cause=sanitize_terminal(redact_endpoint_secrets(str(exc), list(eth_rpc_urls)), max_len=600),
            fix="nothing was signed or broadcast",
        ) from exc
    payload = refund.to_dict()
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="raw_hex"))
    else:
        click.echo(emit(payload, mode="human", human_lines=_lines(refund)))
