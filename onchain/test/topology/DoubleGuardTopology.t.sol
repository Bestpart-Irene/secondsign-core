// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {Safe as Safe141} from "safe-1.4.1/contracts/Safe.sol";
import {SafeProxy as Proxy141} from "safe-1.4.1/contracts/proxies/SafeProxy.sol";
import {Enum as Enum141} from "safe-1.4.1/contracts/common/Enum.sol";
import {BaseGuard} from "safe-1.4.1/contracts/base/GuardManager.sol";

import {Safe as Safe150} from "safe-1.5.0/contracts/Safe.sol";
import {SafeProxy as Proxy150} from "safe-1.5.0/contracts/proxies/SafeProxy.sol";
import {Enum as Enum150} from "safe-1.5.0/contracts/libraries/Enum.sol";
import {BaseTransactionGuard} from "safe-1.5.0/contracts/base/GuardManager.sol";
import {BaseModuleGuard} from "safe-1.5.0/contracts/base/ModuleManager.sol";

/// @notice ONCHAIN-S001 - the double-guard topology, falsified and confirmed on a
/// local chain. This is a `stop_for_human` checkpoint: the no-bypass argument the
/// whole on-chain design rests on is only as good as these executed assertions,
/// and a human must confirm they ran - the 1.4.1 failure *reproduced*, not
/// described - before anything is built on them.
///
/// Coverage is deliberately explicit. This file establishes the core of the
/// argument by execution:
///   1. both pinned releases deploy fresh on one chain, no fork, no RPC secret;
///   2. a transaction guard is invoked on the guarded (`execTransaction`) path;
///   3. on 1.4.1, an enabled module clears the guard with NO guard hook invoked -
///      the failure is reproduced;
///   4. on 1.5.0, the module guard refuses that same guard-clearing call;
///   4b. on 1.5.0, the module guard also refuses the module-path call that would
///       remove the module guard *itself* - closing the self-teardown that would
///       otherwise clear the transaction guard on a now-unguarded module path;
///   5. on 1.5.0, a module-path delegatecall is refused;
///   6. two permanently reverting guards brick the account - the double-failure
///      residual risk, recorded rather than presented as solved.
///
/// STILL OWED for the full slice, and NOT asserted here (a human/expert must add
/// them; the fixed-version result alone is not evidence): the controlled recovery
/// paths under single-guard failure, the relayer-varies-the-submitter-identity
/// proof, the atomic deploy/init/configure sequence, and the separate
/// deployment-manifest canonicality check. No production guard is written (the
/// guards here are minimal test doubles under `test/`, not `onchain/src`).

interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        pure
        returns (uint8 v, bytes32 r, bytes32 s);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function expectRevert() external;
}

/// @dev A transaction guard (1.4.1) that records whether its hook ran. Nothing
/// more: the falsification is about *whether* the guard is consulted, so a guard
/// that only remembers being consulted is the sharpest instrument for it.
contract Recorder141 is BaseGuard {
    bool public invoked;

    function reset() external {
        invoked = false;
    }

    function checkTransaction(
        address,
        uint256,
        bytes memory,
        Enum141.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external override {
        invoked = true;
    }

    function checkAfterExecution(bytes32, bool) external override {}
}

/// @dev A 1.5.0 module guard that refuses the module-path bypass: a `delegatecall`,
/// or a self-call that would change the guard. It only ever narrows the module
/// path - it is a test double for the topology, not a production guard.
contract ModuleGuard150 is BaseModuleGuard {
    bytes4 private constant SET_GUARD = bytes4(keccak256("setGuard(address)"));
    bytes4 private constant SET_MODULE_GUARD = bytes4(keccak256("setModuleGuard(address)"));

    function checkModuleTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum150.Operation operation,
        address
    ) external view override returns (bytes32) {
        if (operation == Enum150.Operation.DelegateCall) {
            revert("SecondSign S001: module-path delegatecall refused");
        }
        // A self-call that changes EITHER guard is a guard-config change, and the
        // module path must never make one - not the transaction guard (test 4)
        // and not the module guard itself (a module that could remove this guard
        // could then clear the transaction guard on an unguarded module path).
        if (to == msg.sender && data.length >= 4) {
            bytes4 selector = bytes4(data);
            if (selector == SET_GUARD || selector == SET_MODULE_GUARD) {
                revert("SecondSign S001: module-path guard change refused");
            }
        }
        return bytes32(0);
    }

    function checkAfterModuleExecution(bytes32, bool) external override {}
}

/// @dev A guard that always reverts - the permanent-failure case.
contract RevertingTxGuard150 is BaseTransactionGuard {
    function checkTransaction(
        address,
        uint256,
        bytes memory,
        Enum150.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external pure override {
        revert("SecondSign S001: transaction guard is down");
    }

    function checkAfterExecution(bytes32, bool) external override {}
}

contract RevertingModuleGuard150 is BaseModuleGuard {
    function checkModuleTransaction(address, uint256, bytes memory, Enum150.Operation, address)
        external
        pure
        override
        returns (bytes32)
    {
        revert("SecondSign S001: module guard is down");
    }

    function checkAfterModuleExecution(bytes32, bool) external override {}
}

/// @dev A rogue enabled module: it moves down the module path with no owner
/// signature, which is precisely the authority a module has.
contract RogueModule {
    function callFromModule141(address safe, address to, bytes memory data)
        external
        returns (bool)
    {
        return Safe141(payable(safe)).execTransactionFromModule(to, 0, data, Enum141.Operation.Call);
    }

    function callFromModule150(address safe, address to, bytes memory data, Enum150.Operation op)
        external
        returns (bool)
    {
        return Safe150(payable(safe)).execTransactionFromModule(to, 0, data, op);
    }
}

contract DoubleGuardTopologyTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant GUARD_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    // keccak256("module_manager.module_guard.address") - Safe 1.5.0 ModuleManager
    bytes32 private constant MODULE_GUARD_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    uint256 private constant AGENT_PK = 0xA11CE;

    event Assertion(string id, string what);

    // --- 1. both releases deploy fresh on one chain -------------------------

    function test_bothReleasesDeployFreshOnOneChain() public {
        (Safe141 safe141,) = _deploy141();
        (Safe150 safe150,) = _deploy150();
        _assertEqStr(safe141.VERSION(), "1.4.1", "1.4.1 did not deploy at its pinned version");
        _assertEqStr(safe150.VERSION(), "1.5.0", "1.5.0 did not deploy at its pinned version");
        emit Assertion("S001-1", "both pinned releases deploy fresh, no fork, no RPC secret");
    }

    // --- 2. the transaction guard is invoked on the guarded path ------------

    function test_transactionGuardIsInvokedOnTheGuardedPath() public {
        (Safe150 safe, address singleton) = _deploy150();
        singleton;
        Recorder141 recorder = new Recorder141(); // 1.4.1/1.5.0 guard shape is identical
        _exec150(
            safe, address(safe), abi.encodeWithSignature("setGuard(address)", address(recorder))
        );
        _assertTrue(!recorder.invoked(), "guard must not have run before any guarded transaction");
        _exec150(safe, address(0xdead), ""); // a benign guarded transaction
        _assertTrue(recorder.invoked(), "the guard was not invoked on execTransaction");
        emit Assertion("S001-2", "a transaction guard runs on the guarded execTransaction path");
    }

    // --- 3. THE reproduction: 1.4.1 module clears the guard, no hook --------

    function test_1_4_1_anEnabledModuleClearsTheGuardWithNoHook() public {
        (Safe141 safe, address agent) = _deploy141();
        Recorder141 recorder = new Recorder141();
        RogueModule rogue = new RogueModule();

        _exec141(
            safe,
            agent,
            address(safe),
            abi.encodeWithSignature("setGuard(address)", address(recorder))
        );
        _exec141(
            safe,
            agent,
            address(safe),
            abi.encodeWithSignature("enableModule(address)", address(rogue))
        );

        // The guard works on the owner-signed path...
        recorder.reset();
        _exec141(safe, agent, address(0xdead), "");
        _assertTrue(recorder.invoked(), "sanity: the guard runs on execTransaction on 1.4.1");

        // ...but the module path never consults it, so the module removes it.
        recorder.reset();
        bool ok = rogue.callFromModule141(
            address(safe), address(safe), abi.encodeWithSignature("setGuard(address)", address(0))
        );
        _assertTrue(
            ok, "1.4.1: the module-path setGuard should succeed (this is the vulnerability)"
        );
        _assertTrue(
            !recorder.invoked(),
            "1.4.1: the guard hook ran on the module path - vuln not reproduced"
        );
        _assertEqAddr(
            _installedGuard(address(safe)), address(0), "1.4.1: the guard was not actually cleared"
        );
        emit Assertion(
            "S001-3", "1.4.1: an enabled module cleared the guard with NO guard hook (reproduced)"
        );
    }

    // --- 4. the fix: 1.5.0 module guard refuses that same call --------------

    function test_1_5_0_theModuleGuardRefusesTheGuardClearingCall() public {
        (Safe150 safe,) = _deploy150();
        Recorder141 recorder = new Recorder141();
        ModuleGuard150 moduleGuard = new ModuleGuard150();
        RogueModule rogue = new RogueModule();

        _exec150(
            safe, address(safe), abi.encodeWithSignature("setGuard(address)", address(recorder))
        );
        _exec150(
            safe,
            address(safe),
            abi.encodeWithSignature("setModuleGuard(address)", address(moduleGuard))
        );
        _exec150(
            safe, address(safe), abi.encodeWithSignature("enableModule(address)", address(rogue))
        );

        bool ok = _rogueTry150(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("setGuard(address)", address(0)),
            Enum150.Operation.Call
        );
        _assertTrue(!ok, "1.5.0: the module guard must refuse the module-path setGuard");
        _assertEqAddr(
            _installedGuard(address(safe)),
            address(recorder),
            "1.5.0: the guard must still be installed"
        );
        emit Assertion(
            "S001-4", "1.5.0: the module guard refused the same module-path guard-clearing call"
        );
    }

    // --- 4b. the module guard refuses removing ITSELF (self-teardown) -------

    /// @dev The bypass the double guard must actually close. A rogue module that
    /// cannot clear the transaction guard (test 4) instead removes the *module*
    /// guard first, then clears the transaction guard on a now-unguarded module
    /// path. A module guard that refuses only `setGuard` leaves this open. The
    /// evidence is state-based, not a bare `!ok`: a benign module call proves the
    /// path is live (so a later refusal is the guard's doing, not a broken setup),
    /// and the module-guard slot proves the guard was never removed.
    function test_1_5_0_theModuleGuardRefusesRemovingItself() public {
        (Safe150 safe,) = _deploy150();
        ModuleGuard150 moduleGuard = new ModuleGuard150();
        RogueModule rogue = new RogueModule();

        _exec150(
            safe,
            address(safe),
            abi.encodeWithSignature("setModuleGuard(address)", address(moduleGuard))
        );
        _exec150(
            safe, address(safe), abi.encodeWithSignature("enableModule(address)", address(rogue))
        );

        // Positive control: a benign module-path call the guard allows goes
        // through, so the refusal below is the guard acting, not a broken setup.
        _assertTrue(
            _rogueTry150(rogue, address(safe), address(0xbeef), "", Enum150.Operation.Call),
            "sanity: a benign module-path call must go through"
        );

        // The attack: remove the module guard itself down the module path.
        bool ok = _rogueTry150(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("setModuleGuard(address)", address(0)),
            Enum150.Operation.Call
        );
        _assertTrue(!ok, "1.5.0: the module guard must refuse a module-path setModuleGuard");
        _assertEqAddr(
            _installedModuleGuard(address(safe)),
            address(moduleGuard),
            "1.5.0: the module guard must still be installed after the attempt"
        );
        emit Assertion(
            "S001-4b",
            "1.5.0: the module guard refused the module-path call that would remove itself"
        );
    }

    // --- 5. a module-path delegatecall is refused on 1.5.0 ------------------

    function test_1_5_0_aModulePathDelegatecallIsRefused() public {
        (Safe150 safe, address agent) = _deploy150();
        agent;
        ModuleGuard150 moduleGuard = new ModuleGuard150();
        RogueModule rogue = new RogueModule();
        _exec150(
            safe,
            address(safe),
            abi.encodeWithSignature("setModuleGuard(address)", address(moduleGuard))
        );
        _exec150(
            safe, address(safe), abi.encodeWithSignature("enableModule(address)", address(rogue))
        );

        bool ok =
            _rogueTry150(rogue, address(safe), address(0xdead), "", Enum150.Operation.DelegateCall);
        _assertTrue(!ok, "1.5.0: a module-path delegatecall must be refused");
        emit Assertion(
            "S001-5", "1.5.0: a module-path delegatecall was refused by the module guard"
        );
    }

    // --- 6. both guards reverting brick the account (residual risk) ---------

    function test_bothGuardsRevertingBrickTheAccount() public {
        (Safe150 safe,) = _deploy150();
        RevertingTxGuard150 txGuard = new RevertingTxGuard150();
        RevertingModuleGuard150 modGuard = new RevertingModuleGuard150();
        RogueModule module = new RogueModule();
        _exec150(
            safe, address(safe), abi.encodeWithSignature("enableModule(address)", address(module))
        );
        _exec150(
            safe,
            address(safe),
            abi.encodeWithSignature("setModuleGuard(address)", address(modGuard))
        );
        _exec150(
            safe, address(safe), abi.encodeWithSignature("setGuard(address)", address(txGuard))
        );

        // The owner path reverts (the tx guard is down)...
        _assertTrue(
            !_tryExec150(safe, address(0xdead), ""),
            "owner path must be dead with the tx guard down"
        );
        // ...and the module path reverts (the module guard is down), including the
        // call that would remove either guard. No-bypass and recoverability are not
        // both available here: the account is bricked.
        _assertTrue(
            !_rogueTry150(
                module,
                address(safe),
                address(safe),
                abi.encodeWithSignature("setGuard(address)", address(0)),
                Enum150.Operation.Call
            ),
            "module path must be dead with the module guard down"
        );
        emit Assertion(
            "S001-6",
            "two permanently reverting guards brick the account - recorded as double-failure residual risk, not solved"
        );
    }

    // --- deployment helpers (fresh, no fork) --------------------------------

    function _deploy141() private returns (Safe141 safe, address agent) {
        agent = vm.addr(AGENT_PK);
        Safe141 singleton = new Safe141();
        safe = Safe141(payable(address(new Proxy141(address(singleton)))));
        address[] memory owners = new address[](1);
        owners[0] = agent;
        safe.setup(owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
    }

    function _deploy150() private returns (Safe150 safe, address agent) {
        agent = vm.addr(AGENT_PK);
        Safe150 singleton = new Safe150();
        safe = Safe150(payable(address(new Proxy150(address(singleton)))));
        address[] memory owners = new address[](1);
        owners[0] = agent;
        safe.setup(owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));
    }

    // --- execution helpers --------------------------------------------------

    function _exec141(Safe141 safe, address, address to, bytes memory data) private {
        _assertTrue(_tryExec141(safe, to, data), "a 1.4.1 setup transaction should have succeeded");
    }

    function _tryExec141(Safe141 safe, address to, bytes memory data) private returns (bool ok) {
        bytes32 h = safe.getTransactionHash(
            to, 0, data, Enum141.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        (ok,) = address(safe).call(_execCalldata141(to, data, _sig(h)));
    }

    function _execCalldata141(address to, bytes memory data, bytes memory sig)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            Safe141.execTransaction.selector,
            to,
            uint256(0),
            data,
            Enum141.Operation.Call,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            sig
        );
    }

    function _exec150(Safe150 safe, address to, bytes memory data) private {
        _assertTrue(_tryExec150(safe, to, data), "a 1.5.0 setup transaction should have succeeded");
    }

    function _tryExec150(Safe150 safe, address to, bytes memory data) private returns (bool ok) {
        bytes32 h = safe.getTransactionHash(
            to, 0, data, Enum150.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );
        (ok,) = address(safe).call(_execCalldata150(to, data, _sig(h)));
    }

    function _execCalldata150(address to, bytes memory data, bytes memory sig)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            Safe150.execTransaction.selector,
            to,
            uint256(0),
            data,
            Enum150.Operation.Call,
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

    /// @dev A module transaction as a real rogue module makes it: a direct call to
    /// the Safe that reverts if the module guard refuses. Low-level here so the
    /// test observes the refusal (ok == false) rather than reverting with it.
    function _rogueTry150(
        RogueModule rogue,
        address safe,
        address to,
        bytes memory data,
        Enum150.Operation op
    ) private returns (bool ok) {
        (ok,) = address(rogue).call(
            abi.encodeWithSelector(RogueModule.callFromModule150.selector, safe, to, data, op)
        );
    }

    function _installedGuard(address safe) private view returns (address) {
        return address(uint160(uint256(vm.load(safe, GUARD_SLOT))));
    }

    function _installedModuleGuard(address safe) private view returns (address) {
        return address(uint160(uint256(vm.load(safe, MODULE_GUARD_SLOT))));
    }

    // --- assertions ---------------------------------------------------------

    function _assertTrue(bool condition, string memory message) private pure {
        if (!condition) revert(message);
    }

    function _assertEqAddr(address a, address b, string memory message) private pure {
        if (a != b) revert(message);
    }

    function _assertEqStr(string memory a, string memory b, string memory message) private pure {
        if (keccak256(bytes(a)) != keccak256(bytes(b))) revert(message);
    }
}
