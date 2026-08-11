// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {BaseModuleGuard} from "safe-1.5.0/contracts/base/ModuleManager.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";

/// @title SecondSignModuleGuard — the constitutional floor on the module path.
/// @notice RED baseline (ONCHAIN-S005): installs on the `checkModuleTransaction`
/// hook but enforces nothing yet, so the module-path invariants in
/// ConstitutionalGuard.t.sol are proven absent before they are proven present.
contract SecondSignModuleGuard is BaseModuleGuard {
    function checkModuleTransaction(address, uint256, bytes memory, Enum.Operation, address)
        external
        override
        returns (bytes32)
    {
        // RED baseline: no enforcement yet.
        return bytes32(0);
    }

    function checkAfterModuleExecution(bytes32, bool) external override {}
}
