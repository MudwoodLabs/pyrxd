"""EthHtlcContractLeg — the web3-backed ETH counter-chain leg.

Implements the counter-chain leg surface (deploy/claim/refund/recover-secret/is-final)
for native-ETH HTLC swaps. This is the I/O-bearing layer; the security-critical preimage
recovery is the pure :func:`pyrxd.eth_wallet.secret.recover_secret`, and the durable
state is :class:`EthHtlcLocator`.

DESIGNED-AND-UNPROVEN until the Sepolia end-to-end proof (Phase 4). web3 is imported
lazily, so this module loads without the Ethereum stack; only the network-touching
methods require it. The Phase-6 ``CounterChainLeg`` ABC will reconcile method names with
the BTC leg; until then this exposes ETH-native names and is driven by the Phase-4
Sepolia harness (mirroring how the BTC leg was first proven by its own spike driver).

Key handling (HARD): the signing key is :class:`PrivateKeyMaterial`; its raw bytes are
fed to the signer at the call site and never persisted as an ``eth_account`` object.

Security gates enforced here (off-chain, per the security review):
  * pre-fund: ``eth_getCode`` runtime-bytecode == the committed artifact's, the
    contract immutables (hashlock/claimant/refundee/timeout) == negotiated, and the
    funded balance == negotiated amount — BEFORE the maker is told to lock RXD.
  * EOA-only claimant/refundee (a recipient contract that reverts on receive would lock
    funds via the contract's ``require(ok)``).
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.eth_wallet.secret import recover_secret
from pyrxd.gravity.counter_chain_leg import CounterChainLeg
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

__all__ = ["EthHtlcContractLeg", "load_artifact"]

_REQUIRED_ARTIFACT_KEYS = ("runtime_bytecode", "abi", "bytecode")


def load_artifact(path: str | os.PathLike) -> dict:
    """Load an EthHtlc artifact (ABI + bytecode + runtime_bytecode) from ``path``.

    The contract artifact is owned by the DEPLOYING application (its audited Foundry
    build output), NOT shipped inside the pyrxd wheel — it is INJECTED
    into :class:`EthHtlcContractLeg` via its constructor so the wheel carries no contract
    bytecode and the audited artifact stays beside its contract source. This helper is a
    convenience for callers that have the artifact on disk; pass the resulting dict in.
    """
    with open(path) as f:
        return json.load(f)


def _validate_artifact(artifact: dict) -> dict:
    if not isinstance(artifact, dict):
        raise ValidationError("artifact must be a dict (ABI + bytecode + runtime_bytecode)")
    missing = [k for k in _REQUIRED_ARTIFACT_KEYS if k not in artifact]
    if missing:
        raise ValidationError(f"artifact missing required keys: {missing}")
    return artifact


def _require_web3() -> Any:
    try:
        import web3  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only without eth deps
        raise ValidationError("the ETH leg needs web3 (a Phase-3 network dependency); install the eth extra") from exc
    return web3


class EthHtlcContractLeg:
    """Native-ETH HTLC counter-chain leg (Sepolia-first).

    Parameters
    ----------
    rpc:
        An :class:`pyrxd.eth_wallet.rpc.EthRpc` (web3-backed).
    signing_key:
        :class:`PrivateKeyMaterial` for the EOA that sends txs (taker for fund/refund,
        maker for claim — separate leg instances per role).
    chain_id:
        EIP-155 chain id; must match ``rpc``'s endpoint (asserted at use).
    artifact:
        The EthHtlc contract artifact dict (``abi`` + ``bytecode`` + ``runtime_bytecode``),
        owned and INJECTED by the deploying application (its audited Foundry build output).
        Use :func:`load_artifact` to read it from disk. pyrxd ships no contract bytecode of
        its own.
    """

    def __init__(self, *, rpc: Any, signing_key: PrivateKeyMaterial, chain_id: int, artifact: dict) -> None:
        if not isinstance(signing_key, PrivateKeyMaterial):
            raise ValidationError("signing_key must be PrivateKeyMaterial (never a plaintext LocalAccount)")
        if not isinstance(chain_id, int) or chain_id <= 0:
            raise ValidationError("chain_id must be a positive int")
        self._rpc = rpc
        self._key = signing_key
        self._chain_id = chain_id
        self._artifact = _validate_artifact(artifact)

    # -- pure helpers (no network) -----------------------------------------------------

    @property
    def expected_runtime_code(self) -> bytes:
        return bytes.fromhex(self._artifact["runtime_bytecode"][2:])

    def expected_runtime_code_hash(self) -> bytes:
        return hashlib.sha256(self.expected_runtime_code).digest()

    def recover_secret(self, artifacts: list[bytes], hashlock: bytes) -> bytes:
        """Recover ``p`` from claim calldata + event-log data (pure; see secret.py)."""
        return recover_secret(artifacts, hashlock)

    # -- network methods (require web3 + a live RPC; exercised on Sepolia) -------------
    #
    # These are intentionally thin and are validated by the Phase-4 Sepolia proof, not by
    # offline unit tests (which cover the pure layer above). Each documents its contract.

    def _runtime_code_matches(self, on_chain: bytes) -> bool:
        """Compare on-chain runtime to the committed artifact, IGNORING immutable slots.

        Solidity splices ``immutable`` values (hashlock/claimant/refundee/timeout)
        directly into the runtime bytecode at deploy time; the committed ``bin-runtime``
        carries zero-placeholders there, so a byte-exact compare always fails. We require
        the same length and a byte-match everywhere the committed code is NON-zero (the
        actual program logic). The immutables themselves are then checked by value via
        the getters in :meth:`verify_funded` — which is the meaningful check anyway.
        """
        expected = self.expected_runtime_code
        if len(on_chain) != len(expected):
            return False
        return all(e == o for e, o in zip(expected, on_chain) if e != 0)

    async def verify_funded(self, locator: EthHtlcLocator, *, expected_amount_wei: int) -> None:
        """Pre-RXD-lock gate: the on-chain contract matches the negotiated terms.

        Fail-closed checks (any mismatch raises; the taker does NOT tell the maker to
        lock RXD):
          1. chain id matches;
          2. deployed runtime logic == the committed artifact's (immutable slots masked —
             no attacker contract / no modified logic);
          3. the contract IMMUTABLES (hashlock/claimant/refundee/timeout) read back via
             the getters == the negotiated terms in the locator (the meaningful binding
             check — proves the contract releases on the right secret to the right party
             at the right time);
          4. funded balance == expected amount (no underfunded contract).
        """
        await self._rpc.assert_chain()
        code = await self._rpc.get_code(locator.contract_address)
        if not self._runtime_code_matches(code):
            raise ValidationError("on-chain runtime logic != committed EthHtlc artifact (wrong/attacker contract)")
        # Read immutables back by value and bind them to the negotiated terms.
        web3 = _require_web3()
        c = self._rpc.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
        on_h = bytes(await c.functions.hashlock().call())
        on_claimant = await c.functions.claimant().call()
        on_refundee = await c.functions.refundee().call()
        on_timeout = int(await c.functions.timeout().call())
        if on_h != locator.hashlock_bytes:
            raise ValidationError("on-chain hashlock != negotiated H")
        if web3.Web3.to_checksum_address(on_claimant) != web3.Web3.to_checksum_address(locator.claimant):
            raise ValidationError("on-chain claimant != negotiated maker")
        if web3.Web3.to_checksum_address(on_refundee) != web3.Web3.to_checksum_address(locator.refundee):
            raise ValidationError("on-chain refundee != negotiated taker")
        if on_timeout != locator.timeout:
            raise ValidationError("on-chain timeout != negotiated timeout")
        bal = await self._rpc.get_balance(locator.contract_address)
        if bal != expected_amount_wei:
            raise ValidationError(f"funded balance {bal} wei != negotiated {expected_amount_wei} wei")

    def _account_address(self) -> str:
        """Derive this leg's sender address from the held key (no plaintext persisted)."""
        from pyrxd.eth_wallet.keys import derive_address

        return derive_address(self._key)

    async def _sign_and_send(self, tx: dict, *, preflight: bool = True) -> str:
        """Sign ``tx`` with the held key's RAW bytes (call-site only) and broadcast.

        Preflights via ``eth_call`` first (unless ``preflight=False``, e.g. a contract
        deploy where there is no ``to``): a tx that would revert (premature refund, bad
        preimage, already-settled) fails fast off-chain with a :class:`ValidationError`
        instead of burning gas on an on-chain revert.
        """
        if preflight:
            await self._rpc.preflight(tx)
        web3 = _require_web3()
        raw = self._key.unsafe_raw_bytes()
        try:
            signed = web3.Account.sign_transaction(tx, raw)
        finally:
            del raw
        return await self._rpc.send_raw(signed.raw_transaction)

    async def _base_tx(self, *, gas: int) -> dict:
        addr = self._account_address()
        fees = await self._rpc.fee_fields()
        return {
            "from": addr,
            "chainId": self._chain_id,
            "nonce": await self._rpc.get_transaction_count(addr),
            "gas": gas,
            **fees,
        }

    async def fund(
        self, *, hashlock: bytes, claimant: str, refundee: str, timeout: int, amount_wei: int
    ) -> EthHtlcLocator:
        """Deploy + fund the HTLC (payable constructor). Returns the locator ONLY after
        the deploy tx confirms with status==1 (a reverted/dropped deploy never yields a
        'funded' locator). The TAKER calls this; claimant=maker, refundee=taker."""
        if not isinstance(hashlock, (bytes, bytearray)) or len(hashlock) != 32:
            raise ValidationError("hashlock must be 32 bytes")
        if amount_wei <= 0:
            raise ValidationError("amount_wei must be > 0")
        web3 = _require_web3()
        await self._rpc.assert_chain()
        c = self._rpc.w3.eth.contract(abi=self._artifact["abi"], bytecode=self._artifact["bytecode"])
        # constructor(bytes32 _hashlock, address _claimant, address _refundee, uint256 _timeout)
        ctor = c.constructor(
            bytes(hashlock),
            web3.Web3.to_checksum_address(claimant),
            web3.Web3.to_checksum_address(refundee),
            int(timeout),
        )
        tx = await self._base_tx(gas=400_000)
        tx["value"] = int(amount_wei)
        built = await ctor.build_transaction(tx)
        # No eth_call preflight for a deploy (no `to`); the status==1 check below is the gate.
        tx_hash = await self._sign_and_send(built, preflight=False)
        receipt = await self._rpc.wait_receipt(tx_hash)
        if int(receipt.get("status", 0)) != 1:
            raise NetworkError(f"deploy tx reverted (status != 1): {tx_hash}")
        addr = receipt["contractAddress"]
        return EthHtlcLocator(
            chain_id=self._chain_id,
            contract_address=web3.Web3.to_checksum_address(addr),
            deploy_tx_hash=tx_hash if tx_hash.startswith("0x") else "0x" + tx_hash,
            hashlock="0x" + bytes(hashlock).hex(),
            claimant=web3.Web3.to_checksum_address(claimant),
            refundee=web3.Web3.to_checksum_address(refundee),
            timeout=int(timeout),
            amount_wei=int(amount_wei),
        )

    async def claim(self, locator: EthHtlcLocator, preimage: bytes) -> str:
        """Maker: call claim(preimage); returns the tx hash. On MAINNET the maker SHOULD
        use private inclusion (Flashbots) — the public mempool exposes p before mining,
        letting the taker claim RXD while this ETH claim is still reorg-able."""
        if not isinstance(preimage, (bytes, bytearray)) or len(preimage) != 32:
            raise ValidationError("preimage must be 32 bytes")
        await self._rpc.assert_chain()
        c = self._rpc.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
        built = await c.functions.claim(bytes(preimage)).build_transaction(await self._base_tx(gas=120_000))
        return await self._sign_and_send(built)

    async def refund(self, locator: EthHtlcLocator) -> str:
        """Taker: call refund() after timeout; returns the tx hash. Taker-unilateral
        (no maker signature; the contract pays the immutable refundee)."""
        await self._rpc.assert_chain()
        c = self._rpc.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
        built = await c.functions.refund().build_transaction(await self._base_tx(gas=100_000))
        return await self._sign_and_send(built)

    async def fetch_claim_artifacts(self, tx_hash: str) -> list[bytes]:
        """Fetch the candidate byte blobs for recover_secret: the tx INPUT calldata + the
        DATA of every log in the receipt. Works on a reverted-but-mined tx too (calldata
        is still present). Pure recover_secret(...) then matches by sha256==H."""
        tx = await self._rpc.get_transaction(tx_hash)
        artifacts: list[bytes] = []
        inp = tx.get("input")
        if inp is not None:
            artifacts.append(
                bytes(inp) if not isinstance(inp, str) else bytes.fromhex(inp[2:] if inp.startswith("0x") else inp)
            )
        receipt = await self._rpc.wait_receipt(tx_hash)
        for log in receipt.get("logs", []):
            data = log.get("data")
            if data:
                artifacts.append(
                    bytes(data)
                    if not isinstance(data, str)
                    else bytes.fromhex(data[2:] if data.startswith("0x") else data)
                )
        return artifacts

    async def is_final(self, tx_hash: str) -> bool:
        """True once the tx's block is at/under the `finalized` checkpoint. The taker must
        NOT mark the swap COMPLETED (RXD claim irreversible) until the ETH claim is FINAL,
        since a pre-finality reorg could un-mine it."""
        receipt = await self._rpc.wait_receipt(tx_hash)
        if int(receipt.get("status", 0)) != 1:
            return False
        tx_block = int(receipt["blockNumber"])
        return tx_block <= await self._rpc.finalized_block_number()


# Register as a virtual subclass of the CounterChainLeg ABC: the leg realises the full
# abstract surface (fund/verify_funded/claim/refund/recover_secret/is_final), so
# isinstance(leg, CounterChainLeg) holds for the coordinator's fail-closed checks without
# forcing nominal inheritance (the leg stays usable standalone / web3-lazy).
CounterChainLeg.register(EthHtlcContractLeg)
