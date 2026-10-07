// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title EthHtlc — minimal native-ETH Hashed Timelock Contract for cross-chain atomic swaps
/// @notice One contract instance == one indivisible swap (deploy-per-swap). The counterparty
///         chain (Radiant) verifies the SAME secret via sha256(preimage)==hashlock, so this
///         contract MUST use sha256 (the 0x02 precompile), NOT keccak (Keccak-256).
///
/// Role (MAKER_SECRET_TAKER_LOCKS_COUNTERCHAIN_FIRST):
///   - The TAKER deploys + funds this contract (msg.value), setting `claimant` = maker,
///     `refundee` = taker (themselves), `timeout` = absolute unix deadline.
///   - The MAKER calls claim(preimage), revealing the preimage (emitted in `Claimed`) and
///     receiving the ETH. Revealing the preimage is the cross-chain message.
///   - If the maker never claims, the TAKER calls refund() after `timeout` to reclaim the ETH.
///
/// Security properties (see docs/plans/2026-05-24-feat-eth-rxd-htlc-atomic-swap-plan.md):
///   - sha256 hashlock (digest-compatible with Bitcoin/Radiant OP_SHA256 over a 32-byte secret).
///   - Checks-Effects-Interactions + single `settled` flag => reentrancy-safe; the value send
///     is the last action and cannot re-enter a still-open swap.
///   - claim requires `block.timestamp < timeout`; refund requires `>= timeout`. The boundary
///     belongs to exactly one path (no overlap), so a reorg cannot let both succeed.
///   - refund is taker-unilateral (no maker signature; recipient is the immutable `refundee`).
///   - EOA-only claimant/refundee is enforced OFF-CHAIN by the pre-fund gate (a recipient
///     contract that reverts on receive would lock funds via the `require(ok)` below).
contract EthHtlc {
    bytes32 public immutable hashlock; // H = sha256(p)
    address payable public immutable claimant; // maker — receives ETH on claim(p)
    address payable public immutable refundee; // taker — receives ETH on refund() after timeout
    uint256 public immutable timeout; // absolute unix deadline (block.timestamp)

    bool private settled; // single mutual-exclusion flag (claim XOR refund, once)

    event Claimed(bytes32 preimage); // preimage NON-indexed so it is recoverable from log data
    event Refunded();

    error AlreadySettled();
    error BadPreimage();
    error Expired();
    error NotYetExpired();
    error SendFailed();
    error ZeroValue();

    constructor(
        bytes32 _hashlock,
        address payable _claimant,
        address payable _refundee,
        uint256 _timeout
    ) payable {
        if (msg.value == 0) revert ZeroValue();
        hashlock = _hashlock;
        claimant = _claimant;
        refundee = _refundee;
        timeout = _timeout;
    }

    /// @notice Maker claims the ETH by revealing the preimage. Callable by anyone, but pays
    ///         only `claimant` — so a mempool front-runner gains nothing (revealing p is the point).
    /// @param preimage the 32-byte secret p such that sha256(p) == hashlock
    function claim(bytes32 preimage) external {
        if (settled) revert AlreadySettled();
        // sha256 precompile (0x02), NOT keccak256 — must match Radiant OP_SHA256.
        // For a bytes32, sha256(abi.encodePacked(preimage)) hashes exactly those 32 bytes
        // (no length prefix / padding), matching hashlib.sha256(p).digest() and OP_SHA256.
        if (sha256(abi.encodePacked(preimage)) != hashlock) revert BadPreimage();
        if (block.timestamp >= timeout) revert Expired();
        settled = true; // EFFECTS before INTERACTION (reentrancy-safe)
        emit Claimed(preimage);
        (bool ok, ) = claimant.call{value: address(this).balance}("");
        if (!ok) revert SendFailed();
    }

    /// @notice Taker reclaims the ETH after the timeout. No maker signature required.
    function refund() external {
        if (settled) revert AlreadySettled();
        if (block.timestamp < timeout) revert NotYetExpired();
        settled = true; // EFFECTS before INTERACTION
        emit Refunded();
        (bool ok, ) = refundee.call{value: address(this).balance}("");
        if (!ok) revert SendFailed();
    }
}
