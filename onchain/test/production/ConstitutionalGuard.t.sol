// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {Safe} from "safe-1.5.0/contracts/Safe.sol";
import {SafeProxy} from "safe-1.5.0/contracts/proxies/SafeProxy.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";

import {SecondSignTransactionGuard} from "../../src/SecondSignTransactionGuard.sol";
import {SecondSignModuleGuard} from "../../src/SecondSignModuleGuard.sol";

/// @notice ONCHAIN-S005 — the production constitutional double guard, proven on a
/// local chain by executed transactions that are refused. This is a
/// `stop_for_human` checkpoint (ADR 0008): the integrity floor the whole 2-of-2
/// co-signer scheme stands on is only as good as these assertions, and a human
/// confirms each invariant is refused by an *executed* transaction — not described
/// — and that the module path is covered, before the account relies on it.
///
/// Run it: `forge test --match-path 'test/production/ConstitutionalGuard.t.sol'`.
/// Every refusal is pinned to the guard's exact revert reason, so a `[PASS]` is
/// the guard acting, not an unrelated Safe revert passing a blind `!ok`.
///
/// What this file establishes by execution, on both hooks:
///   1. SecondSign cannot be removed or diluted as a signer (invariant 1);
///   2. the threshold cannot be changed (invariant 2);
///   3. neither guard can be removed or replaced (invariant 3);
///   4. no module can be enabled/disabled and no delegatecall runs (invariant 4);
///   plus: `setFallbackHandler` is refused, the module path permits exactly the
///   threshold-preserving owner rotation (`swapOwner`) as the recovery seam, and
///   the guard judges no amount or counterparty — a value move to an arbitrary
///   target passes on both paths.
///
/// The guard makes no external call and reads only the transaction and the
/// account, so every refusal here holds with the off-chain engine offline — the
/// suite wires no engine at all. The account being un-reconfigurable does not wait
/// on the engine; the account being unable to *move value* is the co-signer
/// withholding its second signature, a different layer (ONCHAIN-S004).
///
/// The harness is a two-owner, threshold-one Safe: the agent alone can drive
/// `execTransaction`, while every account-control payload below is a valid Safe
/// operation — so the guard's refusal is the only thing standing between the agent
/// and a reconfigured account, and a permissive guard would let it through.

interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        pure
        returns (uint8 v, bytes32 r, bytes32 s);
    function load(address target, bytes32 slot) external view returns (bytes32);
}

/// @dev A rogue enabled module: it moves down the module path with no owner
/// signature, which is precisely the authority an enabled module has. The module
/// path is the one the guard must cover that a single transaction guard misses
/// (ONCHAIN-S001).
contract RogueModule {
    function callFromModule(address safe, address to, bytes memory data, Enum.Operation op)
        external
        returns (bool)
    {
        return Safe(payable(safe)).execTransactionFromModule(to, 0, data, op);
    }
}

/// @dev A benign call target: its fallback accepts anything, so a call the guard
/// permits actually goes through and the test can tell "allowed" from "reverted".
contract Sink {
    fallback() external payable {}
}

contract ConstitutionalGuardTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // keccak256("guard_manager.guard.address") and
    // keccak256("module_manager.module_guard.address") — Safe 1.5.0.
    bytes32 private constant GUARD_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 private constant MODULE_GUARD_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    uint256 private constant AGENT_PK = 0xA11CE;
    address private constant SENTINEL = address(0x1);

    string private constant TX_ACCOUNT_CONTROL =
        "SecondSign: transaction-path account-control change refused";
    string private constant TX_DELEGATECALL = "SecondSign: transaction-path delegatecall refused";
    string private constant MOD_INTEGRITY = "SecondSign: module-path integrity change refused";
    string private constant MOD_DELEGATECALL = "SecondSign: module-path delegatecall refused";

    event Assertion(string id, string what);

    // --- transaction path: every account-control change is refused ----------

    function test_txPath_guardsAreInstalledOnBothHooks() public {
        (Safe safe,, address txGuard, address moduleGuard,) = _deployGuardedSafe();
        _assertEqAddr(_installedGuard(address(safe)), txGuard, "the transaction guard is installed");
        _assertEqAddr(
            _installedModuleGuard(address(safe)), moduleGuard, "the module guard is installed"
        );
        emit Assertion("S005-tx-0", "both hooks carry a SecondSign guard");
    }

    function test_txPath_refusesRemovingSecondSignAsASigner() public {
        (Safe safe, address dummy,,,) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature("removeOwner(address,address,uint256)", _agent(), dummy, 1),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse removeOwner (invariant 1)"
        );
        emit Assertion("S005-tx-1", "invariant 1: a signer cannot be removed on the agent path");
    }

    function test_txPath_refusesSwapOwnerEvenThoughItIsTheRecoveryOp() public {
        (Safe safe, address dummy,,,) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature(
                "swapOwner(address,address,address)", _agent(), dummy, address(0xC0FFEE)
            ),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse swapOwner - the agent reconfigures nothing"
        );
        emit Assertion("S005-tx-1b", "the recovery op itself is refused on the agent path");
    }

    function test_txPath_refusesChangingTheThreshold() public {
        (Safe safe,,,,) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature("changeThreshold(uint256)", uint256(2)),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse changeThreshold (invariant 2)"
        );
        emit Assertion(
            "S005-tx-2", "invariant 2: the threshold cannot be changed on the agent path"
        );
    }

    function test_txPath_refusesReplacingTheTransactionGuard() public {
        (Safe safe,, address txGuard,,) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature("setGuard(address)", address(0)),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse setGuard (invariant 3)"
        );
        _assertEqAddr(
            _installedGuard(address(safe)), txGuard, "the transaction guard must still be installed"
        );
        emit Assertion("S005-tx-3a", "invariant 3: the transaction guard cannot be removed");
    }

    function test_txPath_refusesReplacingTheModuleGuard() public {
        (Safe safe,,, address moduleGuard,) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature("setModuleGuard(address)", address(0)),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse setModuleGuard (invariant 3)"
        );
        _assertEqAddr(
            _installedModuleGuard(address(safe)),
            moduleGuard,
            "the module guard must still be installed"
        );
        emit Assertion("S005-tx-3b", "invariant 3: the module guard cannot be removed either");
    }

    function test_txPath_refusesEnablingAModule() public {
        (Safe safe,,,,) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature("enableModule(address)", address(0xBADBAD)),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse enableModule (invariant 4)"
        );
        emit Assertion("S005-tx-4a", "invariant 4: no module can be enabled on the agent path");
    }

    function test_txPath_refusesDisablingAModule() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature("disableModule(address,address)", SENTINEL, address(rogue)),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse disableModule (invariant 4)"
        );
        emit Assertion("S005-tx-4b", "invariant 4: no module can be disabled on the agent path");
    }

    function test_txPath_refusesSetFallbackHandler() public {
        (Safe safe,,,,) = _deployGuardedSafe();
        _assertOwnerPathReverts(
            safe,
            address(safe),
            abi.encodeWithSignature("setFallbackHandler(address)", address(0xF00D)),
            TX_ACCOUNT_CONTROL,
            "the transaction path must refuse setFallbackHandler"
        );
        emit Assertion(
            "S005-tx-4c", "setFallbackHandler is refused - it alters what the account runs"
        );
    }

    function test_txPath_refusesDelegatecall() public {
        (Safe safe,,,,) = _deployGuardedSafe();
        Sink sink = new Sink();
        _assertOwnerPathRevertsWithOp(
            safe,
            address(sink),
            "",
            Enum.Operation.DelegateCall,
            TX_DELEGATECALL,
            "the transaction path must refuse a delegatecall (invariant 4)"
        );
        emit Assertion("S005-tx-5", "invariant 4: a delegatecall is refused on the agent path");
    }

    function test_txPath_doesNotJudgeAmountOrCounterparty() public {
        (Safe safe,,,,) = _deployGuardedSafe();
        Sink counterparty = new Sink();
        // A large-value transfer to an arbitrary counterparty is a normal call the
        // guard has no opinion on: value is the co-signer's and the engine's
        // question, not the guard's. It passes.
        bool ok = _tryExec(
            safe,
            address(counterparty),
            abi.encodeWithSignature("transfer(address,uint256)", address(0xDEAD), type(uint256).max)
        );
        _assertTrue(ok, "the guard must not judge amount or counterparty on the agent path");
        emit Assertion("S005-tx-6", "integrity only: an arbitrary-value transfer passes the guard");
    }

    // --- module path: subverting changes refused, recovery permitted --------

    function test_modulePath_allowsABenignCall() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        Sink sink = new Sink();
        _assertModuleCallSucceeds(
            rogue,
            address(safe),
            address(sink),
            "",
            Enum.Operation.Call,
            "sanity: a benign module-path call must go through (the path is live)"
        );
        emit Assertion(
            "S005-mod-0", "positive control: the module path is live and allowed calls pass"
        );
    }

    function test_modulePath_refusesReplacingTheTransactionGuard() public {
        (Safe safe,, address txGuard,, RogueModule rogue) = _deployGuardedSafe();
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("setGuard(address)", address(0)),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse setGuard (invariant 3)"
        );
        _assertEqAddr(
            _installedGuard(address(safe)),
            txGuard,
            "the transaction guard must survive the module-path attempt"
        );
        emit Assertion(
            "S005-mod-3a", "invariant 3: the module path cannot clear the transaction guard"
        );
    }

    function test_modulePath_refusesRemovingItself() public {
        (Safe safe,,, address moduleGuard, RogueModule rogue) = _deployGuardedSafe();
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("setModuleGuard(address)", address(0)),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse setModuleGuard - the guard cannot remove itself"
        );
        _assertEqAddr(
            _installedModuleGuard(address(safe)),
            moduleGuard,
            "the module guard must survive its own teardown attempt"
        );
        emit Assertion("S005-mod-3b", "invariant 3: the module guard refuses to remove itself");
    }

    function test_modulePath_refusesChangingTheThreshold() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("changeThreshold(uint256)", uint256(1)),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse changeThreshold (invariant 2)"
        );
        emit Assertion(
            "S005-mod-2", "invariant 2: the threshold cannot be changed on the module path"
        );
    }

    function test_modulePath_refusesAddOwner() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        // addOwnerWithThreshold carries a _threshold argument, so allowing it would
        // let a module change the threshold — invariant 2. Refused, unlike swapOwner.
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", address(0xABCD), 1),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse addOwnerWithThreshold (it carries a threshold change)"
        );
        emit Assertion(
            "S005-mod-2b", "invariant 2: addOwnerWithThreshold is refused on the module path"
        );
    }

    function test_modulePath_refusesRemoveOwner() public {
        (Safe safe, address dummy,,, RogueModule rogue) = _deployGuardedSafe();
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("removeOwner(address,address,uint256)", _agent(), dummy, 1),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse removeOwner (it carries a threshold change)"
        );
        emit Assertion("S005-mod-2c", "invariant 2: removeOwner is refused on the module path");
    }

    function test_modulePath_refusesEnablingAModule() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("enableModule(address)", address(0xBADBAD)),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse enableModule (invariant 4)"
        );
        emit Assertion("S005-mod-4a", "invariant 4: no module can be enabled on the module path");
    }

    function test_modulePath_refusesDisablingAModule() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("disableModule(address,address)", SENTINEL, address(rogue)),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse disableModule (invariant 4)"
        );
        emit Assertion("S005-mod-4b", "invariant 4: no module can be disabled on the module path");
    }

    function test_modulePath_refusesSetFallbackHandler() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature("setFallbackHandler(address)", address(0xF00D)),
            Enum.Operation.Call,
            MOD_INTEGRITY,
            "the module path must refuse setFallbackHandler"
        );
        emit Assertion("S005-mod-4c", "setFallbackHandler is refused on the module path too");
    }

    function test_modulePath_refusesDelegatecall() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        Sink sink = new Sink();
        // Positive control first: a plain Call on the same path is allowed, so the
        // refusal below is the delegatecall branch acting, not a dead path.
        _assertModuleCallSucceeds(
            rogue,
            address(safe),
            address(sink),
            "",
            Enum.Operation.Call,
            "sanity: a benign module-path Call must go through"
        );
        _assertModuleRefusal(
            rogue,
            address(safe),
            address(sink),
            "",
            Enum.Operation.DelegateCall,
            MOD_DELEGATECALL,
            "the module path must refuse a delegatecall (invariant 4)"
        );
        emit Assertion("S005-mod-5", "invariant 4: a module-path delegatecall is refused");
    }

    function test_modulePath_permitsThresholdPreservingRecovery() public {
        (Safe safe, address dummy,,, RogueModule rogue) = _deployGuardedSafe();
        uint256 ownersBefore = safe.getOwners().length;
        uint256 thresholdBefore = safe.getThreshold();
        address recovered = address(0xC0FFEE);

        // swapOwner rotates a signer without touching the owner count or the
        // threshold: the single recovery capability the module path permits. The
        // agent's path refuses even this (see test_txPath_refusesSwapOwner...).
        _assertModuleCallSucceeds(
            rogue,
            address(safe),
            address(safe),
            abi.encodeWithSignature(
                "swapOwner(address,address,address)", _agent(), dummy, recovered
            ),
            Enum.Operation.Call,
            "the module path must permit swapOwner - the threshold-preserving recovery seam"
        );

        _assertTrue(safe.isOwner(recovered), "recovery: the new signer must be an owner");
        _assertTrue(!safe.isOwner(dummy), "recovery: the rotated-out signer must be gone");
        _assertEqUint(
            safe.getOwners().length, ownersBefore, "recovery must not change the owner count"
        );
        _assertEqUint(
            safe.getThreshold(), thresholdBefore, "recovery must not change the threshold"
        );
        emit Assertion(
            "S005-mod-1", "the module path permits exactly the threshold-preserving owner rotation"
        );
    }

    function test_modulePath_doesNotJudgeAmountOrCounterparty() public {
        (Safe safe,,,, RogueModule rogue) = _deployGuardedSafe();
        Sink counterparty = new Sink();
        _assertModuleCallSucceeds(
            rogue,
            address(safe),
            address(counterparty),
            abi.encodeWithSignature("transfer(address,uint256)", address(0xDEAD), type(uint256).max),
            Enum.Operation.Call,
            "the guard must not judge amount or counterparty on the module path"
        );
        emit Assertion("S005-mod-6", "integrity only: an arbitrary-value module transfer passes");
    }

    // --- deployment: a two-owner threshold-one Safe, both guards, one module -

    /// @dev Deploys a fresh guarded Safe. The rogue module is enabled *before* the
    /// guards are installed — once the transaction guard is up, `enableModule` is
    /// refused, which is exactly the bootstrapping the real deployment does in one
    /// atomic setup. Returns the pieces the tests name.
    function _deployGuardedSafe()
        private
        returns (Safe safe, address dummy, address txGuard, address moduleGuard, RogueModule rogue)
    {
        address agent = _agent();
        dummy = vm.addr(0xB0B);

        Safe singleton = new Safe();
        safe = Safe(payable(address(new SafeProxy(address(singleton)))));
        address[] memory owners = new address[](2);
        owners[0] = agent;
        owners[1] = dummy;
        safe.setup(owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));

        rogue = new RogueModule();
        txGuard = address(new SecondSignTransactionGuard());
        moduleGuard = address(new SecondSignModuleGuard());

        _exec(safe, address(safe), abi.encodeWithSignature("enableModule(address)", address(rogue)));
        _exec(safe, address(safe), abi.encodeWithSignature("setModuleGuard(address)", moduleGuard));
        _exec(safe, address(safe), abi.encodeWithSignature("setGuard(address)", txGuard));
    }

    function _agent() private pure returns (address) {
        return vm.addr(AGENT_PK);
    }

    // --- transaction-path execution helpers ---------------------------------

    function _exec(Safe safe, address to, bytes memory data) private {
        _assertTrue(_tryExec(safe, to, data), "a guarded setup transaction should have succeeded");
    }

    function _tryExec(Safe safe, address to, bytes memory data) private returns (bool ok) {
        (ok,) = _ownerCall(safe, to, data, Enum.Operation.Call);
    }

    function _ownerCall(Safe safe, address to, bytes memory data, Enum.Operation op)
        private
        returns (bool ok, bytes memory ret)
    {
        bytes memory sig = _sig(_txHash(safe, to, data, op));
        (ok, ret) = address(safe).call(_execCalldata(to, data, op, sig));
    }

    function _txHash(Safe safe, address to, bytes memory data, Enum.Operation op)
        private
        view
        returns (bytes32)
    {
        return
            safe.getTransactionHash(to, 0, data, op, 0, 0, 0, address(0), address(0), safe.nonce());
    }

    function _execCalldata(address to, bytes memory data, Enum.Operation op, bytes memory sig)
        private
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            Safe.execTransaction.selector,
            to,
            uint256(0),
            data,
            op,
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

    // --- module-path execution helper ---------------------------------------

    function _rogueCall(
        RogueModule rogue,
        address safe,
        address to,
        bytes memory data,
        Enum.Operation op
    ) private returns (bool ok, bytes memory ret) {
        (ok, ret) = address(rogue).call(
            abi.encodeWithSelector(RogueModule.callFromModule.selector, safe, to, data, op)
        );
    }

    // --- assertions ---------------------------------------------------------

    function _assertOwnerPathReverts(
        Safe safe,
        address to,
        bytes memory data,
        string memory expectedReason,
        string memory message
    ) private {
        _assertOwnerPathRevertsWithOp(safe, to, data, Enum.Operation.Call, expectedReason, message);
    }

    function _assertOwnerPathRevertsWithOp(
        Safe safe,
        address to,
        bytes memory data,
        Enum.Operation op,
        string memory expectedReason,
        string memory message
    ) private {
        (bool ok, bytes memory ret) = _ownerCall(safe, to, data, op);
        _assertTrue(!ok, message);
        _assertRevertIs(ret, expectedReason, message);
    }

    function _assertModuleCallSucceeds(
        RogueModule rogue,
        address safe,
        address to,
        bytes memory data,
        Enum.Operation op,
        string memory message
    ) private {
        (bool ok,) = _rogueCall(rogue, safe, to, data, op);
        _assertTrue(ok, message);
    }

    function _assertModuleRefusal(
        RogueModule rogue,
        address safe,
        address to,
        bytes memory data,
        Enum.Operation op,
        string memory expectedReason,
        string memory message
    ) private {
        (bool ok, bytes memory ret) = _rogueCall(rogue, safe, to, data, op);
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

    /// @dev Assert `ret` is exactly `Error(string)` carrying `expectedReason`, so a
    /// refusal is pinned to a specific `revert("...")` and any other revert (a Safe
    /// GS code, a different message) fails the assertion rather than passing it.
    function _assertRevertIs(bytes memory ret, string memory expectedReason, string memory message)
        private
        pure
    {
        if (keccak256(ret) != keccak256(abi.encodeWithSignature("Error(string)", expectedReason))) {
            revert(string.concat(message, " (revert reason was not the guard's)"));
        }
    }
}
