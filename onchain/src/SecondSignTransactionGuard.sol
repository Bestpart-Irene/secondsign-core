// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {BaseTransactionGuard} from "safe-1.5.0/contracts/base/GuardManager.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";

/// @title SecondSignTransactionGuard — the constitutional floor on the agent path.
/// @notice RED baseline (ONCHAIN-S005): installs on the `execTransaction` hook but
/// enforces nothing yet, so the invariants in ConstitutionalGuard.t.sol are proven
/// absent before they are proven present.
contract SecondSignTransactionGuard is BaseTransactionGuard {
    function checkTransaction(
        address,
        uint256,
        bytes memory,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external override {
        // RED baseline: no enforcement yet.
    }

    function checkAfterExecution(bytes32, bool) external override {}
}
