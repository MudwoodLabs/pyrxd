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


def _token_for(locator: Any) -> Any:
    """The :class:`Erc20Token` a token locator is denominated in.

    The pinned registry entry when there is one. A swap on a value-bearing chain can only have used a
    pinned token, so an unpinned one there is refused. On a test chain (or one the registry does not
    know, such as anvil's 31337), an unpinned address is used as it stands: the refund reads only the
    token's address (its balance, and the ``token`` immutable the exact runtime check binds).
    """
    from ..eth_wallet.chains import evm_chain_by_id
    from ..eth_wallet.tokens import Erc20Token, token_by_address

    try:
        return token_by_address(locator.token_address, locator.chain_id)
    except ValidationError:
        try:
            value_bearing = not evm_chain_by_id(locator.chain_id).is_testnet
        except ValidationError:
            value_bearing = False
        if value_bearing:
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
        f"  holds         : {r.contract_balance} {r.asset}",
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
            "  ⚠ Read from ONE endpoint: the contract checks and the nonce are its word only. Pass --eth-rpc-url "
            "more than once (distinct operators) to have them agree."
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


def _open_rpc(urls: tuple[str, ...], chain_id: int) -> Any:
    from ..eth_wallet.multi_rpc import MultiSourceEthRpc
    from ..eth_wallet.rpc import EthRpc

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
    help="Ethereum JSON-RPC URL on the swap's chain. Repeat it (distinct operators) to require agreement.",
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
@click.pass_obj
def swap_build_eth_refund_cmd(
    ctx: CliContext,
    swap_file: Path,
    record_path: Path | None,
    eth_rpc_urls: tuple[str, ...],
    artifact_path: Path,
    eth_key_file: str | None,
) -> None:
    """Sign the TAKER's refund of the ETH counter-leg HTLC and PRINT it. Never broadcasts.

    For a swap whose resume was refused: once the contract's timeout has passed, this signs
    refund() and prints the raw transaction for you to send. The contract and its terms come from
    the swap record, and the contract on chain must match them exactly before anything is signed.
    """
    from ..eth_wallet.htlc_leg import load_artifact
    from ..gravity.watch.cli_secrets import resolve_secret
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
        secret = resolve_secret(None, eth_key_file, KEY_ENV, flag="--eth-key")
        if not secret:
            secret = load_recovery_json(swap_file).get("eth_key_hex") or None
        if not secret:
            raise ValidationError(
                f"no refund key: pass --eth-key-file PATH (mode 0600) or set {KEY_ENV}; the swap file holds no "
                "eth_key_hex"
            )
        key = parse_eth_key(str(secret))
        rpc = _open_rpc(eth_rpc_urls, locator.chain_id)
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

    try:
        refund = _run(_go(), url=eth_rpc_urls[0], scrub=tuple(eth_rpc_urls))
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
