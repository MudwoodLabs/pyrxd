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
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial

__all__ = ["EthHtlcContractLeg", "load_artifact"]

_REQUIRED_ARTIFACT_KEYS = ("runtime_bytecode", "abi", "bytecode")
# Claim-artifact size caps (red-team LOW DoS): a legit claim(bytes32) calldata + Claimed(bytes32)
# log are ~tens of bytes; cap each blob + the aggregate well above that, fail closed past it so a
# malicious RPC cannot feed recover_secret's O(n) scan an unbounded blob.
_MAX_ARTIFACT_BYTES = 64 * 1024
_MAX_ARTIFACT_TOTAL_BYTES = 256 * 1024


def _b(v: Any) -> bytes:
    """Coerce a hex string ('0x..' or '..') or bytes-like to bytes; None/'' -> b''.

    A non-hex string raises a TYPED NetworkError (red-team LOW: these values come from RPC-returned
    log topics/data, so bytes.fromhex's bare ValueError is an untyped-error-contract gap)."""
    if v is None:
        return b""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    s = str(v)
    try:
        return bytes.fromhex(s[2:] if s.startswith("0x") else s)
    except ValueError as exc:
        raise NetworkError(f"RPC returned a non-hex log field: {s[:34]!r}") from exc


def _addr(v: Any) -> str:
    """Normalise an address-ish value to a lowercase hex string for comparison."""
    return str(v or "").lower()


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

    def __init__(
        self,
        *,
        rpc: Any,
        signing_key: PrivateKeyMaterial,
        chain_id: int,
        artifact: dict,
        private_submitter: Any = None,
    ) -> None:
        if not isinstance(signing_key, PrivateKeyMaterial):
            raise ValidationError("signing_key must be PrivateKeyMaterial (never a plaintext LocalAccount)")
        if not isinstance(chain_id, int) or chain_id <= 0:
            raise ValidationError("chain_id must be a positive int")
        if private_submitter is not None and not hasattr(private_submitter, "submit_raw"):
            raise ValidationError("private_submitter must provide submit_raw(raw_tx)->tx_hash")
        self._rpc = rpc
        self._key = signing_key
        self._chain_id = chain_id
        self._artifact = _validate_artifact(artifact)
        # OPTIONAL private-inclusion transport (e.g. Flashbots). When set, the CLAIM — the one tx
        # that reveals the secret p — is submitted privately so the public mempool can't expose p
        # before it mines (a maker on mainnet SHOULD set this; see claim()). All other txs (deploy,
        # fund, refund) use the public path: they carry no secret and need normal mempool inclusion.
        self._private_submitter = private_submitter

    # -- pure helpers (no network) -----------------------------------------------------

    @property
    def chain_id(self) -> int:
        return self._chain_id

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
        """Compare on-chain runtime to the committed artifact, masking committed-zero bytes.

        Solidity splices ``immutable`` values (hashlock/claimant/refundee/timeout)
        directly into the runtime bytecode at deploy time; the committed ``bin-runtime``
        carries zero-placeholders there, so a byte-exact compare always fails. We require
        the same length and a byte-match everywhere the committed code is NON-zero.

        HONESTY / LIMITATION (audit eth_leg_web3 LOW): this masks EVERY committed-zero
        position, which is a SUPERSET of the immutable slots — legitimate zero logic bytes
        (STOP, PUSH1 0x00, leading-zero PUSH operands, metadata padding) are therefore NOT
        verified, so this gate alone does not fully prove "no modified logic". The meaningful
        binding is the immutables-checked-by-getter step in :meth:`verify_funded`; a precise
        compare that masks ONLY the artifact's ``immutableReferences`` offset ranges (and
        byte-matches every other position, zeros included) is a hardening follow-up that
        requires the injected artifact to carry ``immutableReferences``. Not exploitable in
        the current self-deploy wiring (the taker deploys its own contract), but the advertised
        "no attacker contract" strength is bounded by this until the slot-accurate compare lands.
        """
        expected = self.expected_runtime_code
        if len(on_chain) != len(expected):
            return False
        return all(e == o for e, o in zip(expected, on_chain) if e != 0)

    async def verify_funded(
        self, locator: EthHtlcLocator, *, expected_amount_wei: int, block_identifier: str | int | None = None
    ) -> None:
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
          4. claimant and refundee are EOAs (empty code) — a contract recipient that
             reverts on ``receive`` would brick claim/refund via the contract's
             ``require(ok)``;
          5. funded balance == expected amount (no underfunded contract).

        ``block_identifier`` (red-team HIGH TOCTOU): pin EVERY read to one block. The taker's
        fund-time self-verify reads 'latest' (None). The MAKER's pre-lock re-verify passes
        ``'finalized'`` so a reorg cannot re-deploy a DIFFERENT contract at the same CREATE
        address (EVM addresses are (deployer,nonce)-derived) between verify and the RXD lock —
        a finalized deploy is non-reorgable. All getters + get_code + get_balance honour it.
        """
        await self._rpc.assert_chain()
        code = await self._rpc.get_code(locator.contract_address, block_identifier)
        if not self._runtime_code_matches(code):
            raise ValidationError("on-chain runtime logic != committed EthHtlc artifact (wrong/attacker contract)")
        # Read immutables back by value and bind them to the negotiated terms.
        web3 = _require_web3()
        c = self._rpc.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
        _bid = "latest" if block_identifier is None else block_identifier
        on_h = bytes(await c.functions.hashlock().call(block_identifier=_bid))
        on_claimant = await c.functions.claimant().call(block_identifier=_bid)
        on_refundee = await c.functions.refundee().call(block_identifier=_bid)
        on_timeout = int(await c.functions.timeout().call(block_identifier=_bid))
        if on_h != locator.hashlock_bytes:
            raise ValidationError("on-chain hashlock != negotiated H")
        if web3.Web3.to_checksum_address(on_claimant) != web3.Web3.to_checksum_address(locator.claimant):
            raise ValidationError("on-chain claimant != negotiated maker")
        if web3.Web3.to_checksum_address(on_refundee) != web3.Web3.to_checksum_address(locator.refundee):
            raise ValidationError("on-chain refundee != negotiated taker")
        if on_timeout != locator.timeout:
            raise ValidationError("on-chain timeout != negotiated timeout")
        # EOA-only claimant/refundee: empty code == EOA. A contract recipient that reverts on
        # receive would lock the funds via the HTLC's require(ok) on the ETH transfer.
        # Pin these to the SAME block as the code/immutables reads above (audit LOW-R1): at
        # 'finalized' the EOA-ness of claimant/refundee and the funded balance must be read at the
        # non-reorgable checkpoint too, not the reorg-able tip — else a reorg could flip an EOA to a
        # reverting contract, or show a balance the finalized state does not have.
        if await self._rpc.get_code(locator.claimant, block_identifier):
            raise ValidationError("claimant has contract code (not an EOA); a reverting recipient could lock funds")
        if await self._rpc.get_code(locator.refundee, block_identifier):
            raise ValidationError("refundee has contract code (not an EOA); a reverting recipient could lock funds")
        bal = await self._rpc.get_balance(locator.contract_address, block_identifier)
        # Lower bound, not exact-equal (red-team LOW): an attacker can force-send 1 wei (selfdestruct
        # / coinbase) to a contract, so an `== expected` check is griefable into a permanent verify
        # failure. Reject UNDER-funding; tolerate dust over-funding (any extra ETH is paid to whoever
        # wins the swap — a deliberate, documented policy). The HTLC claim/refund still moves the
        # full balance, so over-funding only ever benefits the eventual recipient.
        if bal < expected_amount_wei:
            raise ValidationError(f"funded balance {bal} wei < negotiated {expected_amount_wei} wei (under-funded)")

    def _account_address(self) -> str:
        """Derive this leg's sender address from the held key (no plaintext persisted)."""
        from pyrxd.eth_wallet.keys import derive_address

        return derive_address(self._key)

    async def _sign_and_send(self, tx: dict, *, preflight: bool = True, private: bool = False) -> str:
        """Sign ``tx`` with the held key's RAW bytes (call-site only) and broadcast.

        Preflights via ``eth_call`` first (unless ``preflight=False``, e.g. a contract
        deploy where there is no ``to``): a tx that would revert (premature refund, bad
        preimage, already-settled) fails fast off-chain with a :class:`ValidationError`
        instead of burning gas on an on-chain revert.

        ``private=True`` routes the signed tx through the injected ``private_submitter`` (e.g.
        Flashbots) instead of the public mempool — used ONLY for the claim, which reveals ``p``.
        If no submitter is injected, ``private`` falls back to the public path (the privacy
        property is then NOT provided — the caller opted out by not supplying a submitter).
        """
        if preflight:
            await self._rpc.preflight(tx)
        web3 = _require_web3()
        raw = self._key.unsafe_raw_bytes()
        try:
            signed = web3.Account.sign_transaction(tx, raw)
        finally:
            del raw
        if private and self._private_submitter is not None:
            return str(await self._private_submitter.submit_raw(signed.raw_transaction))
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
        # Deploy gas: the contract's runtime CODE DEPOSIT alone is 200 gas/byte (EthHtlc's
        # ~2.1 KB runtime ≈ 418k) + constructor + base tx ≈ 510k measured on Anvil. 400k
        # out-of-gas-reverted the deploy (Phase-4 finding); 800k gives comfortable margin (you
        # pay gasUsed, not the limit). A per-artifact eth_estimateGas is the robust follow-up.
        tx = await self._base_tx(gas=800_000)
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
        letting the taker claim RXD while this ETH claim is still reorg-able.

        Routed through the injected ``private_submitter`` when one is supplied (``private=True``);
        otherwise it goes to the public mempool (the privacy property is then NOT provided — the
        operator opted out by not injecting a submitter).

        PREIMAGE-LEAK FIX (red-team MEDIUM): the off-chain ``eth_call`` preflight sends the claim
        calldata — which CONTAINS p — to the (public) RPC, defeating private inclusion before the
        private submit even runs. So when a private submitter IS injected we SKIP the preflight
        (the whole point is that p must not touch the public RPC); the on-chain revert protection
        the preflight gave is traded for p-privacy, which is the correct trade for the reveal tx.
        On the public-fallback path (no submitter) p goes public anyway, so the preflight stays."""
        if not isinstance(preimage, (bytes, bytearray)) or len(preimage) != 32:
            raise ValidationError("preimage must be 32 bytes")
        await self._rpc.assert_chain()
        c = self._rpc.w3.eth.contract(address=locator.contract_address, abi=self._artifact["abi"])
        built = await c.functions.claim(bytes(preimage)).build_transaction(await self._base_tx(gas=120_000))
        # Skip the p-leaking preflight when going private (submitter present).
        preflight = self._private_submitter is None
        return await self._sign_and_send(built, preflight=preflight, private=True)

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
        is still present). Pure recover_secret(...) then matches by sha256==H.

        SIZE-BOUNDED (red-team LOW): recover_secret does an O(n) sliding-window sha256 scan, so a
        malicious RPC returning attacker-sized calldata/log data is a CPU/memory DoS. A legitimate
        ``claim(bytes32)`` calldata + ``Claimed(bytes32)`` log are ~tens of bytes; we cap each blob
        and the aggregate well above that and fail closed past the cap rather than scan unbounded."""
        tx = await self._rpc.get_transaction(tx_hash)
        artifacts: list[bytes] = []
        total = 0

        def _add(raw) -> None:
            nonlocal total
            b = bytes(raw) if not isinstance(raw, str) else bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
            if len(b) > _MAX_ARTIFACT_BYTES:
                raise NetworkError(f"claim artifact blob {len(b)} B exceeds cap {_MAX_ARTIFACT_BYTES}")
            total += len(b)
            if total > _MAX_ARTIFACT_TOTAL_BYTES:
                raise NetworkError(f"claim artifacts total {total} B exceeds cap {_MAX_ARTIFACT_TOTAL_BYTES}")
            artifacts.append(b)

        inp = tx.get("input")
        if inp is not None:
            _add(inp)
        receipt = await self._rpc.wait_receipt(tx_hash)
        for log in receipt.get("logs", []):
            data = log.get("data")
            if data:
                _add(data)
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

    async def claim_finality_verdict(self, tx_hash: str) -> CounterClaimFinality:
        """The POINT-IN-TIME counter-leg finality verdict for the maker's ETH claim, from the
        post-Merge ``finalized`` checkpoint (NOT a confirmation depth — see
        :class:`CounterClaimFinality`):

          * the claim's block is at/under ``finalized`` → ``FINAL``;
          * otherwise (not yet finalized, OR reverted/dropped ``status != 1``) →
            ``NOT_YET_FINAL_LIVE``.

        This is a stateless single observation: it never emits ``COUNTER_CHAIN_NOT_FINALIZING``.
        That verdict means the chain is *not advancing* finalization, which can only be judged
        across time (post-Merge ``finalized`` advances at epoch boundaries, ~6.4 min, so a
        single non-advance is normal, not a stall). Detecting a genuine non-finality stall —
        finalized stuck for ≥ a patience window of epochs — is the coordinator's polling-loop
        responsibility (Phase-3 wiring), not this point-in-time producer, which would otherwise
        false-positive on any fast poll. ETH finality is not a depth, so the verdict carries no
        ``confirmations`` / ``required_depth``.

        MALICIOUS-RPC HARDENING (red-team HIGH, single-source finality): ``finalized_block_number``
        rejects a finalized > head over-report, and we bind the receipt's ``blockHash`` to the
        CANONICAL block at ``blockNumber`` (a fabricated receipt height is caught when its hash !=
        the canonical hash) — so a naive lying RPC cannot make a non-final claim read FINAL. This
        does NOT defend a fully-consistent malicious provider (one that lies coherently about the
        whole chain): a real-value path MUST use a multi-source finality quorum (≥2 independent
        providers must agree the claim is final). That quorum is DEFERRED to the audit-gated
        real-value track; the dust/pre-audit path accepts a single trusted provider.
        """
        receipt = await self._rpc.wait_receipt(tx_hash)
        if int(receipt.get("status", 0)) != 1:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        tx_block = int(receipt["blockNumber"])
        # Bind the receipt to the canonical chain, FAIL-CLOSED (red-team MEDIUM): a lying receipt
        # blockNumber is caught when its blockHash != the canonical hash at that height. The binding
        # inputs MUST be present — an honest mined receipt always carries blockHash and the canonical
        # block at a real height always has a hash. A MISSING receipt blockHash or an EMPTY canonical
        # hash therefore means "cannot prove canonicality" => NOT_YET_FINAL_LIVE, NEVER FINAL.
        # (Previously these two cases skipped the binding and fell through to the trivial
        # `tx_block <= finalized`, so a naive lying RPC could make a non-final claim read FINAL just
        # by OMITTING blockHash — a strictly lazier attack than the coherent-MITM residual below.)
        receipt_hash = receipt.get("blockHash")
        if receipt_hash is None:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        canonical = await self._rpc.canonical_block_hash(tx_block)
        if not canonical or bytes(receipt_hash) != canonical:
            # Not bound to the canonical chain at the height it claims → not final/live.
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        finalized = await self._rpc.finalized_block_number()  # rejects finalized > head (fail-closed)
        if tx_block <= finalized:
            return CounterClaimFinality(state=CounterClaimState.FINAL)
        return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)

    async def assert_claim_provenance(self, tx_hash: str, *, contract_address: str, preimage: bytes) -> None:
        """Provenance gate (R6): the maker's claim tx MUST target THIS swap's HTLC contract
        instance AND emit the revealed secret ``p`` from it — the ETH analogue of the BTC
        "claim tx spends our funding outpoint" check (``_assert_claim_tx_spends_our_htlc``).

        Each swap deploys a FRESH HTLC contract at a unique CREATE address (recorded in the
        locator after :meth:`verify_funded`), so the contract address is per-swap-unique
        exactly like a BTC funding outpoint. The contract's claim path emits
        ``Claimed(bytes32 preimage)`` with the SECRET ``p`` in the (non-indexed) log data. This
        leg targets the PER-SWAP-deploy ``EthHtlc.sol`` model (one fresh contract per swap,
        ``claim(bytes32 preimage)`` + immutable hashlock/claimant/refundee/timeout getters that
        :meth:`verify_funded` reads back). NB the sibling repo's canonical ``HashedTimelock.sol``
        is a DIFFERENT shared-multi-swap model (``claim(bytes32 swapId, bytes32 preimage)``, no
        per-swap immutables) NOT compatible with this leg — Phase 4 must inject an
        ``EthHtlc.sol``-shaped artifact and reconcile/pin the exact event selector
        (``keccak('Claimed(bytes32)')``) rather than the current ABI-free p-in-log match.
        ``recover_secret`` matches
        ``sha256(p)==H`` over the supplied tx but TRUSTS that the tx belongs to this swap; we
        verify that here, fail-closed (NOT via ``tx.to`` — that rejected legitimate claims routed
        through a smart-contract wallet / multicall, red-team MEDIUM — but via the strictly-stronger
        log-emitter binding):

          * ``receipt.status == 1`` — the claim actually succeeded (the ETH moved; a reverted
            tx never paid the maker even if ``p`` sits in its calldata);
          * a log emitted BY ``contract_address`` whose data carries the SECRET ``p`` — the
            on-chain ``Claimed(p)`` event. We bind to ``p``, NOT the public hashlock ``H``:
            ``H`` is negotiated openly and reused on both legs (so an ``H``-match adds no
            authenticity), and the deployed contract NEVER re-emits ``H`` (it is a constructor
            immutable) — an ``H``-in-log gate would reject every legitimate claim. ``p`` is
            secret until the maker reveals it, so ``p`` appearing in a log from our unique
            contract is a genuine, swap-specific proof of a real claim on it.

        ``preimage`` is the value the coordinator already recovered via ``scrape_secret`` and
        re-verified ``sha256(p)==H``, so passing it here adds no trust assumption. Any RPC
        error propagates and aborts the claim — also fail-closed. The redundant receipt read
        vs :meth:`fetch_claim_artifacts` is deliberate (correctness over a saved round-trip).
        """
        want = _addr(contract_address)
        p = self._p32(preimage)
        # The BINDING is: a successful tx that EMITS a Claimed(p)-style log FROM our per-swap-unique
        # contract carrying the secret p. We do NOT require tx.to == our contract (red-team MEDIUM):
        # that rejected a legitimate claim routed through a smart-contract wallet / ERC-4337 / a
        # multicall (tx.to is the wallet/entrypoint, but the INNER call to our HTLC still emits
        # Claimed(p) FROM our contract). The log-emitter==our-contract + p-in-log check is strictly
        # stronger and already pins the swap: a cross-swap claim (even one reusing H) emits from a
        # DIFFERENT contract address, so no log from `want` carries p and the gate fails closed.
        receipt = await self._rpc.wait_receipt(tx_hash)
        if int(receipt.get("status", 0)) != 1:
            raise ValidationError("claim tx did not succeed (status != 1); refusing to treat it as a valid claim")
        for log in receipt.get("logs", []):
            if _addr(log.get("address")) != want:
                continue  # only logs EMITTED BY our per-swap contract count
            try:
                blob = b"".join(_b(topic) for topic in log.get("topics", [])) + _b(log.get("data"))
            except NetworkError:
                # A malformed (non-hex) topic/data from the RPC must NOT abort the whole scan and
                # hide a legitimate Claimed(p) in another log (red-team LOW). Skip this entry.
                continue
            if p in blob:
                return
        raise ValidationError(
            "no Claimed(p) event from this swap's HTLC contract carries the revealed preimage; "
            "refusing to scrape p (wrong or cross-swap claim tx)"
        )

    @staticmethod
    def _p32(preimage: bytes) -> bytes:
        if not isinstance(preimage, (bytes, bytearray)) or len(preimage) != 32:
            raise ValidationError("preimage must be 32 bytes")
        return bytes(preimage)


# Register as a virtual subclass of the CounterChainLeg ABC: the leg realises the full
# abstract surface (fund/verify_funded/claim/refund/recover_secret/is_final), so
# isinstance(leg, CounterChainLeg) holds for the coordinator's fail-closed checks without
# forcing nominal inheritance (the leg stays usable standalone / web3-lazy).
CounterChainLeg.register(EthHtlcContractLeg)
