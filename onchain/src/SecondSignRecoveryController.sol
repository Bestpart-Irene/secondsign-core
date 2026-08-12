// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";

interface ISafeModule {
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (bool success);
}

/// @title SecondSignRecoveryController — the bounded user of the swapOwner capability.
/// @notice ADR 0008's module guard permits `swapOwner` on the module path but bounds
/// nothing about who may use it or when. This controller is that bound (ADR 0009):
/// enabled as the account's sole module, it is the only path to `swapOwner`, and it
/// is a narrow one — one configured initiator, one owner-rotation, after one
/// timelock the account itself can veto, one-shot.
///
/// Because ADR 0008's guards refuse `enableModule` on both paths, the module set is
/// frozen once the guards are installed; enabling this controller as the sole module
/// at setup makes it permanently the only module that can reach `swapOwner`. The
/// controller has no path to any other account-control operation: it never encodes
/// `setGuard`, `changeThreshold`, `enableModule`, `setFallbackHandler` or a
/// `delegatecall`, so the only reconfiguration it can cause is an owner-rotation,
/// which leaves the owner count and the threshold unchanged (invariant 2 holds
/// through recovery).
contract SecondSignRecoveryController {
    /// @notice The account this controller can recover — set once, at construction.
    address public immutable safe;
    /// @notice The sole address permitted to open and execute a recovery (the
    /// customer's cold recovery key). A class of caller is never admitted.
    address public immutable recoveryInitiator;
    /// @notice The timelock every recovery must wait out before it can execute.
    uint256 public immutable delay;

    struct Pending {
        bool active;
        uint64 readyAt;
        address prevOwner;
        address oldOwner;
        address newOwner;
    }

    Pending private _pending;

    string internal constant NOT_INITIATOR = "SecondSign recovery: caller is not the initiator";
    string internal constant NOT_SAFE = "SecondSign recovery: caller is not the account";
    string internal constant NO_PENDING = "SecondSign recovery: no pending recovery";
    string internal constant TIMELOCK = "SecondSign recovery: timelock has not elapsed";
    string internal constant SWAP_FAILED = "SecondSign recovery: owner rotation failed";
    string internal constant BAD_CONFIG = "SecondSign recovery: zero address in configuration";

    event RecoveryRequested(address prevOwner, address oldOwner, address newOwner, uint256 readyAt);
    event RecoveryCancelled(address oldOwner, address newOwner);
    event RecoveryExecuted(address oldOwner, address newOwner);

    constructor(address safe_, address recoveryInitiator_, uint256 delay_) {
        if (safe_ == address(0) || recoveryInitiator_ == address(0)) revert(BAD_CONFIG);
        safe = safe_;
        recoveryInitiator = recoveryInitiator_;
        delay = delay_;
    }

    /// @notice Open a recovery to rotate `oldOwner` out for `newOwner`. Only the
    /// configured initiator may call this; it records the rotation and starts the
    /// timelock but executes nothing. A new request replaces any pending one, so the
    /// initiator can correct a mistake before the delay elapses.
    function requestRecovery(address prevOwner, address oldOwner, address newOwner) external {
        if (msg.sender != recoveryInitiator) revert(NOT_INITIATOR);
        uint64 readyAt = uint64(block.timestamp + delay);
        _pending = Pending({
            active: true,
            readyAt: readyAt,
            prevOwner: prevOwner,
            oldOwner: oldOwner,
            newOwner: newOwner
        });
        emit RecoveryRequested(prevOwner, oldOwner, newOwner, readyAt);
    }

    /// @notice Veto the pending recovery. Only the account acting as itself (a normal
    /// `execTransaction`, which on a live account is the 2-of-2 co-signer agreeing)
    /// may cancel — not the initiator, not a lone owner. This stops a stolen recovery
    /// key from completing a hostile rotation while the account's signers are intact.
    function cancelRecovery() external {
        if (msg.sender != safe) revert(NOT_SAFE);
        address oldOwner = _pending.oldOwner;
        address newOwner = _pending.newOwner;
        delete _pending;
        emit RecoveryCancelled(oldOwner, newOwner);
    }

    /// @notice Execute the pending recovery once its timelock has elapsed. Only the
    /// initiator may call this, and it rotates exactly the recorded owner — the
    /// executed rotation is the one that was requested and sat out the delay, never a
    /// substituted one. One-shot: the request is cleared before the external call.
    function executeRecovery() external {
        if (msg.sender != recoveryInitiator) revert(NOT_INITIATOR);
        Pending memory p = _pending;
        if (!p.active) revert(NO_PENDING);
        if (block.timestamp < p.readyAt) revert(TIMELOCK);

        // Clear before the external call: one-shot, and no re-entrant replay.
        delete _pending;

        bool ok = ISafeModule(safe).execTransactionFromModule(
            safe,
            0,
            abi.encodeWithSignature(
                "swapOwner(address,address,address)", p.prevOwner, p.oldOwner, p.newOwner
            ),
            Enum.Operation.Call
        );
        if (!ok) revert(SWAP_FAILED);
        emit RecoveryExecuted(p.oldOwner, p.newOwner);
    }

    /// @notice Whether a recovery is currently pending.
    function hasPendingRecovery() external view returns (bool) {
        return _pending.active;
    }

    /// @notice When the pending recovery becomes executable (0 if none is pending).
    function recoveryReadyAt() external view returns (uint256) {
        return _pending.active ? _pending.readyAt : 0;
    }
}
