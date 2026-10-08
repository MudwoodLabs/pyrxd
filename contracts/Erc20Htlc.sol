// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

/// @title Erc20Htlc — per-swap HTLC holding an ERC-20 (USDC) for RXD ↔ token swaps.
/// @notice The token counterpart of the per-swap-deploy `EthHtlc.sol` that pyrxd's
///         `EthHtlcContractLeg` drives. One fresh contract per swap, so the CREATE address is
///         per-swap-unique and serves as the provenance anchor exactly as a BTC funding outpoint
///         does. This is deliberately NOT the shared-multi-swap `HashedTimelock` model: a shared
///         contract would be a single freeze-point for every swap at once (see FREEZE below).
///
/// @dev **Funding is a push, not a pull.** A payable constructor can hold ETH; it cannot pull an
///      ERC-20, because `transferFrom` needs an allowance granted to an address that does not yet
///      exist. So the funder simply `transfer`s the token to this address after deployment, and
///      `claim`/`refund` sweep the whole balance. Consequences, all deliberate:
///
///      * No allowance is ever created — no approve race, no dangling allowance to revoke, no
///        `forceApprove` dance for tokens that require a reset-to-zero.
///      * "Deployed" no longer implies "funded". The counterparty is protected by the off-chain
///        `verify_funded` balance check, which is what actually protected them before too: the
///        coordinator already documents that "an ETH HTLC contract address commits to immutables,
///        not the funded balance".
///      * Sweeping resolves donation residue. Anyone can send tokens here; the winner takes them
///        rather than leaving them stranded forever. This mirrors the native leg, whose
///        `verify_funded` is likewise a LOWER bound because anyone can force-send wei.
///
/// @dev **FREEZE — the trust caveat.** USDC can blacklist an address. If the claimant is frozen
///      while this contract is funded, `claim` reverts; if the preimage is already public on the
///      Radiant side, the counterparty sweeps their leg while the frozen party recovers nothing.
///      Atomicity is therefore conditional on the issuer not intervening. Nothing in this contract
///      can fix that — the mitigation is off-chain and temporal: check the blacklist immediately
///      before publishing the preimage. Per-swap deployment keeps the blast radius to one swap.
contract Erc20Htlc {
    /// @notice sha256(preimage) — SHA-256, not keccak, so one preimage proves both legs
    ///         (Radiant's OP_SHA256 and this contract).
    bytes32 public immutable hashlock;
    address public immutable claimant;
    address public immutable refundee;
    /// @notice Unix seconds; refund is allowed at/after this instant.
    uint256 public immutable timeout;
    /// @notice The ONE token this swap is denominated in. Pinned at construction so a caller
    ///         cannot be handed a different asset than the one they priced.
    address public immutable token;
    /// @notice Amount in the token's own BASE UNITS (USDC has 6 decimals, not 18).
    uint256 public immutable amount;

    bool public settled;

    /// @dev The preimage is NON-INDEXED on purpose: pyrxd scrapes the secret from the log DATA.
    ///      Indexing it would store only its hash and silently break secret recovery.
    event Claimed(bytes32 preimage);
    event Refunded();

    error AlreadySettled();
    error BadPreimage();
    error Expired();
    error NotYetExpired();
    error Underfunded();
    error NothingToRefund();
    error TransferFailed();
    error ZeroValue();
    error ZeroAddress();

    constructor(
        bytes32 _hashlock,
        address _claimant,
        address _refundee,
        uint256 _timeout,
        address _token,
        uint256 _amount
    ) {
        if (_amount == 0) revert ZeroValue();
        if (_claimant == address(0) || _refundee == address(0) || _token == address(0)) {
            revert ZeroAddress();
        }
        hashlock = _hashlock;
        claimant = _claimant;
        refundee = _refundee;
        timeout = _timeout;
        token = _token;
        amount = _amount;
    }

    /// @notice Reveal the preimage and sweep the balance to the claimant.
    /// @dev The `Underfunded` check is fund-safety, not tidiness: claiming PUBLISHES the preimage,
    ///      which lets the counterparty take the other leg. Sweeping whatever happens to be here
    ///      would let a claimant reveal the secret in exchange for a partial balance — paying for
    ///      the other leg in full and being paid a fraction. Refuse instead, and the preimage stays
    ///      secret until the contract actually holds what was promised.
    ///      Error order, shared with EthHtlc: AlreadySettled, then Expired, then BadPreimage (then
    ///      Underfunded, which EthHtlc has no counterpart for). The state and the clock come before
    ///      the caller's input. `amount` is non-zero by construction, so this can never settle a
    ///      contract that holds nothing.
    function claim(bytes32 preimage) external {
        if (settled) revert AlreadySettled();
        if (block.timestamp >= timeout) revert Expired();
        if (sha256(abi.encodePacked(preimage)) != hashlock) revert BadPreimage();

        uint256 balance = _balance();
        if (balance < amount) revert Underfunded();

        // Checks-effects-interactions: settle BEFORE the external call. No ReentrancyGuard —
        // the supported token has no transfer callbacks, and CEI is the actual defence.
        settled = true;
        emit Claimed(preimage);
        _sweep(claimant, balance);
    }

    /// @notice After the timeout, return everything to the refundee.
    /// @dev No `Underfunded` check here — refunding a partial balance is strictly better than
    ///      stranding it, and no secret is revealed by refunding.
    ///
    ///      But an EMPTY balance is refused, and refused WITHOUT settling. Funding is a push that
    ///      follows the deploy, so a contract can pass its timeout holding nothing (the push failed,
    ///      or was never sent). Settling it then would refund nothing and leave `settled` set for
    ///      good, so tokens pushed afterwards could be moved by neither `claim` nor `refund`. The
    ///      balance is read (a staticcall) before the state write; the transfer still comes after it.
    function refund() external {
        if (settled) revert AlreadySettled();
        if (block.timestamp < timeout) revert NotYetExpired();
        uint256 balance = _balance();
        if (balance == 0) revert NothingToRefund();

        settled = true;
        emit Refunded();
        _sweep(refundee, balance);
    }

    function _balance() internal view returns (uint256) {
        (bool ok, bytes memory data) = token.staticcall(
            abi.encodeWithSelector(0x70a08231, address(this)) // balanceOf(address)
        );
        if (!ok || data.length < 32) revert TransferFailed();
        return abi.decode(data, (uint256));
    }

    /// @dev SafeERC20-style: some ERC-20s (USDT is the canonical case) return NOTHING rather than
    ///      a bool, so `IERC20(token).transfer(...)` reverts on them while decoding the absent
    ///      return. Treat "did not revert, returned nothing" as success. USDC itself returns a
    ///      bool, so this is insurance rather than a requirement — cheap, and it removes a whole
    ///      failure class if the pinned token set ever widens.
    ///      Neither caller passes 0 (claim requires at least `amount`, which is non-zero; refund
    ///      refuses an empty balance), so the early return below is a guard, not a path.
    function _sweep(address to, uint256 value) internal {
        if (value == 0) return;
        (bool ok, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, value) // transfer(address,uint256)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}
