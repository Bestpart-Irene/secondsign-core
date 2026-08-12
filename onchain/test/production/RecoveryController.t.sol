// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {Safe} from "safe-1.5.0/contracts/Safe.sol";
import {SafeProxy} from "safe-1.5.0/contracts/proxies/SafeProxy.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";

import {SecondSignTransactionGuard} from "../../src/SecondSignTransactionGuard.sol";
import {SecondSignModuleGuard} from "../../src/SecondSignModuleGuard.sol";
import {SecondSignRecoveryController} from "../../src/SecondSignRecoveryController.sol";

/// @notice ONCHAIN-S010 — the recovery controller, the single bounded user of the
/// swapOwner capability the double guard (ONCHAIN-S005) permits on the module path.
/// This is a `stop_for_human` checkpoint (ADR 0009): recovery is the one deliberate
/// hole in invariant 1, and a human confirms by executed transactions that it is
/// bounded — one initiator, one owner-rotation, one timelock the account can veto —
/// and cannot become the bypass it exists to survive.
///
/// Run it: `forge test --match-path 'test/production/RecoveryController.t.sol'`.
/// Every refusal is pinned to the controller's exact revert reason.
///
/// The harness is a two-owner, threshold-one Safe (agent + an old SecondSign key)
/// with the two S005 guards installed and the controller enabled as the sole
/// module — the real setup: because S005 refuses `enableModule` on both paths, the
/// module set is frozen once the guards are up, so the controller is permanently
/// the only module that can reach `swapOwner`.

interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        pure
        returns (uint8 v, bytes32 r, bytes32 s);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
}

contract RecoveryControllerTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 private constant GUARD_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 private constant MODULE_GUARD_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    uint256 private constant AGENT_PK = 0xA11CE;
    uint256 private constant SS_OLD_PK = 0x5EC0;
    uint256 private constant INITIATOR_PK = 0xBEEF;
    address private constant SENTINEL = address(0x1);
    address private constant NEW_SIGNER = address(0xC0FFEE);
    uint256 private constant DELAY = 3 days;

    string private constant NOT_INITIATOR = "SecondSign recovery: caller is not the initiator";
    string private constant NOT_SAFE = "SecondSign recovery: caller is not the account";
    string private constant NO_PENDING = "SecondSign recovery: no pending recovery";
    string private constant TIMELOCK = "SecondSign recovery: timelock has not elapsed";

    event Assertion(string id, string what);

    // --- the recovery capability works, bounded by the timelock -------------

    function test_recovery_rotatesTheLostSignerAfterTheTimelock() public {
        (Safe safe, SecondSignRecoveryController controller) = _deployGuardedSafe();
        address agent = vm.addr(AGENT_PK);
        address ssOld = vm.addr(SS_OLD_PK);
        uint256 ownersBefore = safe.getOwners().length;
        uint256 thresholdBefore = safe.getThreshold();

        vm.prank(_initiator());
        controller.requestRecovery(agent, ssOld, NEW_SIGNER);

        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(_initiator());
        controller.executeRecovery();

        _assertTrue(safe.isOwner(NEW_SIGNER), "the new signer must be an owner after recovery");
        _assertTrue(!safe.isOwner(ssOld), "the lost signer must be rotated out");
        _assertEqUint(safe.getOwners().length, ownersBefore, "recovery must not change owner count");
        _assertEqUint(
            safe.getThreshold(), thresholdBefore, "recovery must not change the threshold"
        );
        emit Assertion(
            "S010-1", "a lost signer is rotated out after the timelock, count+threshold held"
        );
    }

    function test_recovery_beforeTheTimelockIsRefused() public {
        (Safe safe, SecondSignRecoveryController controller) = _deployGuardedSafe();
        vm.prank(_initiator());
        controller.requestRecovery(vm.addr(AGENT_PK), vm.addr(SS_OLD_PK), NEW_SIGNER);

        // No warp: the delay has not elapsed.
        _assertControllerCall(
            _initiator(),
            abi.encodeWithSelector(SecondSignRecoveryController.executeRecovery.selector),
            controller,
            TIMELOCK,
            "executeRecovery before readyAt must be refused"
        );
        _assertTrue(!safe.isOwner(NEW_SIGNER), "no rotation may happen before the timelock");
        emit Assertion("S010-2", "execution before the timelock is refused");
    }

    // --- only the single configured initiator ------------------------------

    function test_onlyTheInitiatorCanRequest() public {
        (, SecondSignRecoveryController controller) = _deployGuardedSafe();
        _assertControllerCall(
            vm.addr(AGENT_PK), // the agent is not the recovery initiator
            abi.encodeWithSelector(
                SecondSignRecoveryController.requestRecovery.selector,
                vm.addr(AGENT_PK),
                vm.addr(SS_OLD_PK),
                NEW_SIGNER
            ),
            controller,
            NOT_INITIATOR,
            "a non-initiator must not open a recovery"
        );
        emit Assertion("S010-3a", "only the configured initiator can request a recovery");
    }

    function test_onlyTheInitiatorCanExecute() public {
        (, SecondSignRecoveryController controller) = _deployGuardedSafe();
        vm.prank(_initiator());
        controller.requestRecovery(vm.addr(AGENT_PK), vm.addr(SS_OLD_PK), NEW_SIGNER);
        vm.warp(block.timestamp + DELAY + 1);

        _assertControllerCall(
            vm.addr(AGENT_PK),
            abi.encodeWithSelector(SecondSignRecoveryController.executeRecovery.selector),
            controller,
            NOT_INITIATOR,
            "a non-initiator must not execute a pending recovery"
        );
        emit Assertion("S010-3b", "only the configured initiator can execute a recovery");
    }

    // --- the account's own authority can veto; nothing else ----------------

    function test_theAccountCanVetoDuringTheDelay() public {
        (Safe safe, SecondSignRecoveryController controller) = _deployGuardedSafe();
        vm.prank(_initiator());
        controller.requestRecovery(vm.addr(AGENT_PK), vm.addr(SS_OLD_PK), NEW_SIGNER);

        // The account, acting as itself through execTransaction, cancels.
        _exec(
            safe,
            address(controller),
            abi.encodeWithSelector(SecondSignRecoveryController.cancelRecovery.selector)
        );

        vm.warp(block.timestamp + DELAY + 1);
        _assertControllerCall(
            _initiator(),
            abi.encodeWithSelector(SecondSignRecoveryController.executeRecovery.selector),
            controller,
            NO_PENDING,
            "a vetoed recovery must not execute even after the delay"
        );
        _assertTrue(!safe.isOwner(NEW_SIGNER), "a vetoed recovery must not rotate anything");
        emit Assertion("S010-4a", "the account's own authority vetoes a pending recovery");
    }

    function test_onlyTheAccountCanVeto() public {
        (, SecondSignRecoveryController controller) = _deployGuardedSafe();
        vm.prank(_initiator());
        controller.requestRecovery(vm.addr(AGENT_PK), vm.addr(SS_OLD_PK), NEW_SIGNER);

        // Neither the initiator nor a stranger is the account.
        _assertControllerCall(
            _initiator(),
            abi.encodeWithSelector(SecondSignRecoveryController.cancelRecovery.selector),
            controller,
            NOT_SAFE,
            "a caller that is not the account must not cancel"
        );
        emit Assertion("S010-4b", "only the account, not the initiator, can veto");
    }

    // --- one-shot: a cleared request cannot be replayed --------------------

    function test_anExecutedRecoveryCannotBeReplayed() public {
        (, SecondSignRecoveryController controller) = _deployGuardedSafe();
        vm.prank(_initiator());
        controller.requestRecovery(vm.addr(AGENT_PK), vm.addr(SS_OLD_PK), NEW_SIGNER);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(_initiator());
        controller.executeRecovery();

        _assertControllerCall(
            _initiator(),
            abi.encodeWithSelector(SecondSignRecoveryController.executeRecovery.selector),
            controller,
            NO_PENDING,
            "an executed recovery must not be replayable"
        );
        emit Assertion("S010-5", "a recovery is one-shot - a cleared request cannot be replayed");
    }

    // --- confinement: the effect is owner-rotation and nothing else --------

    function test_recovery_touchesOnlyTheOwnerSet() public {
        (Safe safe, SecondSignRecoveryController controller) = _deployGuardedSafe();
        address txGuard = _installedGuard(address(safe));
        address moduleGuard = _installedModuleGuard(address(safe));
        uint256 thresholdBefore = safe.getThreshold();

        vm.prank(_initiator());
        controller.requestRecovery(vm.addr(AGENT_PK), vm.addr(SS_OLD_PK), NEW_SIGNER);
        vm.warp(block.timestamp + DELAY + 1);
        vm.prank(_initiator());
        controller.executeRecovery();

        // The only thing a recovery may change is which key is an owner. The
        // guards, the threshold and the module set are untouched — the controller
        // has no path to any account-control operation other than swapOwner.
        _assertEqAddr(_installedGuard(address(safe)), txGuard, "the transaction guard is untouched");
        _assertEqAddr(
            _installedModuleGuard(address(safe)), moduleGuard, "the module guard is untouched"
        );
        _assertEqUint(safe.getThreshold(), thresholdBefore, "the threshold is untouched");
        _assertTrue(
            safe.isModuleEnabled(address(controller)),
            "the module set is untouched (controller stays)"
        );
        emit Assertion(
            "S010-6", "recovery's only effect is owner-rotation; guards/threshold/modules held"
        );
    }

    // --- deployment ---------------------------------------------------------

    function _deployGuardedSafe()
        private
        returns (Safe safe, SecondSignRecoveryController controller)
    {
        address agent = vm.addr(AGENT_PK);
        address ssOld = vm.addr(SS_OLD_PK);

        Safe singleton = new Safe();
        safe = Safe(payable(address(new SafeProxy(address(singleton)))));
        address[] memory owners = new address[](2);
        owners[0] = agent;
        owners[1] = ssOld;
        safe.setup(owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));

        controller = new SecondSignRecoveryController(address(safe), _initiator(), DELAY);
        address txGuard = address(new SecondSignTransactionGuard());
        address moduleGuard = address(new SecondSignModuleGuard());

        // Enable the controller *before* the guards freeze the module set.
        _exec(
            safe,
            address(safe),
            abi.encodeWithSignature("enableModule(address)", address(controller))
        );
        _exec(safe, address(safe), abi.encodeWithSignature("setModuleGuard(address)", moduleGuard));
        _exec(safe, address(safe), abi.encodeWithSignature("setGuard(address)", txGuard));
    }

    function _initiator() private pure returns (address) {
        return vm.addr(INITIATOR_PK);
    }

    // --- execution + assertion helpers -------------------------------------

    function _exec(Safe safe, address to, bytes memory data) private {
        bytes memory sig = _sig(_txHash(safe, to, data));
        (bool ok,) = address(safe).call(_execCalldata(to, data, sig));
        _assertTrue(ok, "a guarded setup transaction should have succeeded");
    }

    function _txHash(Safe safe, address to, bytes memory data) private view returns (bytes32) {
        return safe.getTransactionHash(
            to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
    }

    function _execCalldata(address to, bytes memory data, bytes memory sig)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            Safe.execTransaction.selector,
            to,
            uint256(0),
            data,
            Enum.Operation.Call,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            sig
        );
    }

    function _sig(bytes32 hash) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Prank `caller`, make one low-level call to the controller, and assert it
    /// reverts at exactly the controller's expected reason. A bare `!ok` would pass
    /// on any revert; pinning the reason keeps the refusal the controller's.
    function _assertControllerCall(
        address caller,
        bytes memory data,
        SecondSignRecoveryController controller,
        string memory expectedReason,
        string memory message
    ) private {
        vm.prank(caller);
        (bool ok, bytes memory ret) = address(controller).call(data);
        _assertTrue(!ok, message);
        _assertRevertIs(ret, expectedReason, message);
    }

    function _installedGuard(address safe) private view returns (address) {
        return address(uint160(uint256(vm.load(safe, GUARD_SLOT))));
    }

    function _installedModuleGuard(address safe) private view returns (address) {
        return address(uint160(uint256(vm.load(safe, MODULE_GUARD_SLOT))));
    }

    function _assertTrue(bool condition, string memory message) private pure {
        if (!condition) revert(message);
    }

    function _assertEqAddr(address a, address b, string memory message) private pure {
        if (a != b) revert(message);
    }

    function _assertEqUint(uint256 a, uint256 b, string memory message) private pure {
        if (a != b) revert(message);
    }

    function _assertRevertIs(bytes memory ret, string memory expectedReason, string memory message)
        private
        pure
    {
        if (keccak256(ret) != keccak256(abi.encodeWithSignature("Error(string)", expectedReason))) {
            revert(string.concat(message, " (revert reason was not the controller's)"));
        }
    }
}
