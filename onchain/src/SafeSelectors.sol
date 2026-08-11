// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

/// @title The Safe account-control function selectors the guards reason about.
/// @notice Every entry here is an `authorized` (self-call only) entrypoint on a
/// Safe that reconfigures the account — its owners, its threshold, its two guards,
/// its modules, or its fallback handler. The selectors are computed from the
/// function signatures, not copied from any Safe source; the *policy* over them —
/// which to refuse on which path — lives in the two guards, not here.
library SafeSelectors {
    bytes4 internal constant SET_GUARD = bytes4(keccak256("setGuard(address)"));
    bytes4 internal constant SET_MODULE_GUARD = bytes4(keccak256("setModuleGuard(address)"));
    bytes4 internal constant CHANGE_THRESHOLD = bytes4(keccak256("changeThreshold(uint256)"));
    bytes4 internal constant ADD_OWNER_WITH_THRESHOLD =
        bytes4(keccak256("addOwnerWithThreshold(address,uint256)"));
    bytes4 internal constant REMOVE_OWNER =
        bytes4(keccak256("removeOwner(address,address,uint256)"));
    bytes4 internal constant SWAP_OWNER = bytes4(keccak256("swapOwner(address,address,address)"));
    bytes4 internal constant ENABLE_MODULE = bytes4(keccak256("enableModule(address)"));
    bytes4 internal constant DISABLE_MODULE = bytes4(keccak256("disableModule(address,address)"));
    bytes4 internal constant SET_FALLBACK_HANDLER = bytes4(keccak256("setFallbackHandler(address)"));
}
