// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {BaseModuleGuard} from "safe-1.5.0/contracts/base/ModuleManager.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";
import {SafeSelectors} from "./SafeSelectors.sol";

/// @title SecondSignModuleGuard — the constitutional floor on the module path.
/// @notice The Safe Module Guard that closes the module-path bypass a single
/// transaction guard leaves open (ONCHAIN-S001): a module transaction takes a
/// separate path, and without this hook it could clear the transaction guard or
/// move value with no signature. Like the transaction guard it enforces integrity,
/// not value (ADR 0008).
///
/// The module path is asymmetric to the agent path, and that asymmetry is the
/// recovery seam. It refuses every integrity-subverting reconfiguration —
/// `setGuard`, `setModuleGuard`, `changeThreshold`, `enableModule`,
/// `disableModule`, `setFallbackHandler`, and `delegatecall` — and it also refuses
/// `addOwnerWithThreshold` and `removeOwner`, because each carries a `_threshold`
/// argument and would let a module change the threshold (invariant 2). The one
/// owner operation it permits is `swapOwner`: it rotates a signer without touching
/// the owner count or the threshold, so a lost SecondSign key can be replaced while
/// the 2-of-2 arrangement is preserved bit-for-bit. That is the sole recovery
/// capability, and the agent's transaction path forbids even it. What bounds *who*
/// may use it — an approved, unexpired recovery — is the RecoveryController (a
/// later slice); v1 runs zero enabled modules as defence in depth until then.
contract SecondSignModuleGuard is BaseModuleGuard {
    string internal constant DELEGATECALL_REFUSED = "SecondSign: module-path delegatecall refused";
    string internal constant INTEGRITY_REFUSED = "SecondSign: module-path integrity change refused";

    function checkModuleTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation operation,
        address
    ) external view override returns (bytes32) {
        if (operation == Enum.Operation.DelegateCall) {
            revert(DELEGATECALL_REFUSED);
        }
        // Same self-call reasoning as the transaction guard: an account-control
        // change appears as `to == the Safe` (== msg.sender). The module path
        // refuses the subverting ones and permits only the threshold-preserving
        // owner rotation.
        if (to == msg.sender && data.length >= 4 && _subvertsIntegrity(bytes4(data))) {
            revert(INTEGRITY_REFUSED);
        }
        return bytes32(0);
    }

    function checkAfterModuleExecution(bytes32, bool) external override {}

    /// @dev Whether `selector` subverts the account's integrity on the module path.
    /// `swapOwner` is deliberately excluded — it is the recovery capability, the one
    /// owner operation that leaves the owner count and threshold untouched. Its
    /// omission here is the whole point of the asymmetry, not an oversight.
    function _subvertsIntegrity(bytes4 selector) private pure returns (bool) {
        if (selector == SafeSelectors.SWAP_OWNER) {
            return false;
        }
        return selector == SafeSelectors.SET_GUARD || selector == SafeSelectors.SET_MODULE_GUARD
            || selector == SafeSelectors.CHANGE_THRESHOLD
            || selector == SafeSelectors.ADD_OWNER_WITH_THRESHOLD
            || selector == SafeSelectors.REMOVE_OWNER || selector == SafeSelectors.ENABLE_MODULE
            || selector == SafeSelectors.DISABLE_MODULE
            || selector == SafeSelectors.SET_FALLBACK_HANDLER;
    }
}
