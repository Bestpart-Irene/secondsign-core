// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {Safe as Safe141} from "safe-1.4.1/contracts/Safe.sol";
import {Safe as Safe150} from "safe-1.5.0/contracts/Safe.sol";

/// @notice Proves the verification toolchain is real, and pins the external facts
/// the on-chain design depends on.
///
/// This is the smoke test for the Solidity gate, not the topology falsification --
/// ONCHAIN-S001 owns that. What it establishes is narrower and still load-bearing:
/// both pinned Safe releases build and deploy in one suite, module guard
/// configuration exists on 1.5.0 and not on 1.4.1, and the self-authorised
/// gate on that configuration behaves as the design assumes. If the CI job were
/// an empty shell, none of these assertions could have produced a result.
contract PinnedReleasesTest {
    /// @dev Present as an external function on 1.5.0's ModuleManager, absent on 1.4.1's.
    bytes4 private constant SET_MODULE_GUARD = bytes4(keccak256("setModuleGuard(address)"));

    function test_pinnedVersionsAreTheOnesTheDesignAssumes() public {
        Safe141 safe141 = new Safe141();
        Safe150 safe150 = new Safe150();

        _assertEqString(safe141.VERSION(), "1.4.1", "1.4.1 singleton reports another version");
        _assertEqString(safe150.VERSION(), "1.5.0", "1.5.0 singleton reports another version");
    }

    /// @notice The version difference the double-guard topology rests on, asserted
    /// by behaviour rather than by reading the sources.
    ///
    /// On 1.5.0 the selector resolves to a real self-authorised function, so an
    /// outside caller is rejected. On 1.4.1 the selector resolves to nothing and
    /// the call is absorbed by the fallback path, which is exactly why a module
    /// path on that version has no guard to answer to.
    function test_moduleGuardConfigurationExistsOnlyOnTheFixedVersion() public {
        address safe141 = address(new Safe141());
        address safe150 = address(new Safe150());
        bytes memory configure = abi.encodeWithSelector(SET_MODULE_GUARD, address(0));

        (bool accepted150,) = safe150.call(configure);
        _assertTrue(
            !accepted150, "1.5.0 must reject module guard configuration from an outside caller"
        );

        (bool accepted141, bytes memory returned141) = safe141.call(configure);
        _assertTrue(accepted141, "1.4.1 has no such selector; the call should reach the fallback");
        _assertTrue(returned141.length == 0, "1.4.1 must not answer a module guard call with data");
    }

    function _assertTrue(bool condition, string memory message) private pure {
        if (!condition) {
            revert(message);
        }
    }

    function _assertEqString(string memory left, string memory right, string memory message)
        private
        pure
    {
        if (keccak256(bytes(left)) != keccak256(bytes(right))) {
            revert(message);
        }
    }
}
