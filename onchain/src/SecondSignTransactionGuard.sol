// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {BaseTransactionGuard} from "safe-1.5.0/contracts/base/GuardManager.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";
import {SafeSelectors} from "./SafeSelectors.sol";

/// @title SecondSignTransactionGuard — the constitutional floor on the agent path.
/// @notice The Safe Transaction Guard that keeps the 2-of-2 co-signer arrangement
/// un-subvertable on the `execTransaction` path. It enforces integrity, not value
/// (ADR 0008): it judges no amount, counterparty or velocity — a normal transfer
/// or approve passes, and whether that transfer is *allowed* is the co-signer's
/// question, answered by whether the second signature exists. What it refuses is
/// every attempt by the agent to reconfigure the account out from under the
/// co-signer.
///
/// On this path every account-control change is refused, including all three owner
/// operations: the agent reconfigures nothing. The one recovery capability
/// (`swapOwner`) lives on the module path (SecondSignModuleGuard), not here. The
/// guard makes no external call and reads only the transaction, so it holds with
/// the off-chain engine offline.
contract SecondSignTransactionGuard is BaseTransactionGuard {
    string internal constant DELEGATECALL_REFUSED =
        "SecondSign: transaction-path delegatecall refused";
    string internal constant ACCOUNT_CONTROL_REFUSED =
        "SecondSign: transaction-path account-control change refused";

    function checkTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external view override {
        // A delegatecall runs foreign code in the account's own storage, so it can
        // rewrite the owners and the guard slots directly, bypassing every selector
        // check below. Refused outright (invariant 4).
        if (operation == Enum.Operation.DelegateCall) {
            revert(DELEGATECALL_REFUSED);
        }
        // Every Safe account-control entrypoint is `authorized`: it executes only as
        // a self-call, so a reconfiguration always appears as `to == the Safe`
        // (== msg.sender here, since the Safe is calling its own guard). On the
        // agent path we refuse all of them (invariants 1-4 and setFallbackHandler).
        if (to == msg.sender && data.length >= 4 && _isAccountControl(bytes4(data))) {
            revert(ACCOUNT_CONTROL_REFUSED);
        }
    }

    function checkAfterExecution(bytes32, bool) external override {}

    /// @dev Whether `selector` is one of the nine account-control entrypoints. On
    /// the transaction path all of them are refused; the module guard permits
    /// exactly `swapOwner` of the set, which is why the two guards keep their own
    /// predicate rather than sharing one.
    function _isAccountControl(bytes4 selector) private pure returns (bool) {
        return selector == SafeSelectors.SET_GUARD || selector == SafeSelectors.SET_MODULE_GUARD
            || selector == SafeSelectors.CHANGE_THRESHOLD
            || selector == SafeSelectors.ADD_OWNER_WITH_THRESHOLD
            || selector == SafeSelectors.REMOVE_OWNER || selector == SafeSelectors.SWAP_OWNER
            || selector == SafeSelectors.ENABLE_MODULE || selector == SafeSelectors.DISABLE_MODULE
            || selector == SafeSelectors.SET_FALLBACK_HANDLER;
    }
}
