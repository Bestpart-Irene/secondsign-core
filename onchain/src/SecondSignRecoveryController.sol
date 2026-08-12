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

/// @title SecondSignRecoveryController — bounded user of the swapOwner capability.
/// @notice RED baseline (ONCHAIN-S010): the recovery state machine with its four
/// bounds — single initiator, timelock, account-only veto, one-shot — deliberately
/// omitted, so RecoveryController.t.sol proves each bound absent before present.
contract SecondSignRecoveryController {
    address public immutable safe;
    address public immutable recoveryInitiator;
    uint256 public immutable delay;

    struct Pending {
        bool active;
        uint64 readyAt;
        address prevOwner;
        address oldOwner;
        address newOwner;
    }

    Pending private _pending;

    string internal constant NO_PENDING = "SecondSign recovery: no pending recovery";
    string internal constant SWAP_FAILED = "SecondSign recovery: owner rotation failed";

    constructor(address safe_, address recoveryInitiator_, uint256 delay_) {
        safe = safe_;
        recoveryInitiator = recoveryInitiator_;
        delay = delay_;
    }

    function requestRecovery(address prevOwner, address oldOwner, address newOwner) external {
        // RED baseline: no initiator check.
        _pending = Pending({
            active: true,
            readyAt: uint64(block.timestamp + delay),
            prevOwner: prevOwner,
            oldOwner: oldOwner,
            newOwner: newOwner
        });
    }

    function cancelRecovery() external {
        // RED baseline: no account-only check.
        _pending.active = false;
    }

    function executeRecovery() external {
        Pending memory p = _pending;
        require(p.active, NO_PENDING);
        // RED baseline: no initiator check, no timelock check, no one-shot clear.
        bool ok = ISafeModule(safe).execTransactionFromModule(
            safe,
            0,
            abi.encodeWithSignature(
                "swapOwner(address,address,address)", p.prevOwner, p.oldOwner, p.newOwner
            ),
            Enum.Operation.Call
        );
        require(ok, SWAP_FAILED);
    }

    function hasPendingRecovery() external view returns (bool) {
        return _pending.active;
    }
}
