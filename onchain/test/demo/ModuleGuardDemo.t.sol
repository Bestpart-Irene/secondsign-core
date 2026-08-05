// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {Safe} from "safe-1.5.0/contracts/Safe.sol";
import {SafeProxy} from "safe-1.5.0/contracts/proxies/SafeProxy.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";
import {BaseTransactionGuard, ITransactionGuard} from "safe-1.5.0/contracts/base/GuardManager.sol";
import {BaseModuleGuard, IModuleGuard} from "safe-1.5.0/contracts/base/ModuleManager.sol";
import {IERC165} from "safe-1.5.0/contracts/interfaces/IERC165.sol";

/// @notice DEMO ONLY — the second half of the double guard, illustrative, NOT the
/// production guard and NOT the ONCHAIN-S001 proof.
///
/// A transaction guard only sees `execTransaction`. A Safe *module* moves value
/// down a different path (`execTransactionFromModule`) that the transaction guard
/// never touches — so a rogue module is a way around it. That gap is exactly the
/// pre-1.5.0 bypass. Safe 1.5.0 adds a second hook, the *module guard*, and
/// guarding both paths is what makes the guard a *double* guard.
///
/// This file shows it in two phases with the same attack — a rogue module signing
/// `approve(attacker, 2^256-1)`:
///
///   phase 1 — a transaction guard is installed, but no module guard: the rogue
///             module drains the wallet down the module path. The blind spot.
///   phase 2 — the module guard is installed too: the same attack is refused.
///
/// One `DemoGuard` implements both hooks (one policy, two entry points); the point
/// is that it must be installed on *both* to cover both paths. `src/` stays empty
/// per `foundry.toml`; this lives under `test/` and ships nothing.
///
/// Run it:  forge test --match-path 'test/demo/ModuleGuardDemo.t.sol' -vvv

interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        pure
        returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address msgSender) external;
}

interface ISafeModuleExec {
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (bool success);
}

contract DemoToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount; // underflows (reverts) without allowance
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev A compromised module: once enabled, it signs a token approval down the
/// module path, with no owner signature required.
contract RogueModule {
    function drain(address safe, address token, address spender, uint256 amount)
        external
        returns (bool)
    {
        return ISafeModuleExec(safe).execTransactionFromModule(
            token,
            0,
            abi.encodeWithSignature("approve(address,uint256)", spender, amount),
            Enum.Operation.Call
        );
    }
}

/// @dev One policy, both hooks. Installed on `setGuard` it covers `execTransaction`;
/// installed on `setModuleGuard` it covers the module path. The cap is the same.
contract DemoGuard is BaseTransactionGuard, BaseModuleGuard {
    address public immutable token;
    uint256 public immutable approvalCap;

    bytes4 private constant APPROVE = bytes4(keccak256("approve(address,uint256)"));

    constructor(address token_, uint256 approvalCap_) {
        token = token_;
        approvalCap = approvalCap_;
    }

    function _enforceApprovalCap(address to, bytes memory data) private view {
        if (data.length < 0x44) {
            return;
        }
        bytes4 selector;
        assembly {
            selector := mload(add(data, 0x20))
        }
        if (to == token && selector == APPROVE) {
            uint256 amount;
            assembly {
                amount := mload(add(data, 0x44))
            }
            require(amount <= approvalCap, "SecondSign demo: approval over cap");
        }
    }

    function checkTransaction(
        address to,
        uint256,
        bytes memory data,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address
    ) external view override {
        _enforceApprovalCap(to, data);
    }

    function checkModuleTransaction(address to, uint256, bytes memory data, Enum.Operation, address)
        external
        view
        override
        returns (bytes32)
    {
        _enforceApprovalCap(to, data);
        return bytes32(0);
    }

    function checkAfterExecution(bytes32, bool) external override {}

    function checkAfterModuleExecution(bytes32, bool) external override {}

    function supportsInterface(bytes4 interfaceId)
        external
        pure
        override(BaseTransactionGuard, BaseModuleGuard)
        returns (bool)
    {
        return interfaceId == type(ITransactionGuard).interfaceId
            || interfaceId == type(IModuleGuard).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}

contract ModuleGuardDemoTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant AGENT_PK = 0xA11CE;
    uint256 private constant APPROVAL_CAP = 1_000e18;

    event Narrate(string phase, string outcome);

    Safe private safe;
    DemoToken private token;
    DemoGuard private guard;
    RogueModule private rogue;
    address private agent;
    address private constant ATTACKER_1 = address(0xBAD1);
    address private constant ATTACKER_2 = address(0xBAD2);

    function test_theModuleGuardClosesTheModulePathBlindSpot() public {
        agent = vm.addr(AGENT_PK);

        Safe singleton = new Safe();
        safe = Safe(payable(address(new SafeProxy(address(singleton)))));
        address[] memory owners = new address[](1);
        owners[0] = agent;
        safe.setup(owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));

        token = new DemoToken();
        token.mint(address(safe), 10_000e18);
        guard = new DemoGuard(address(token), APPROVAL_CAP);
        rogue = new RogueModule();

        // A transaction guard is installed, and a rogue module is enabled.
        _exec(address(safe), abi.encodeWithSignature("setGuard(address)", address(guard)));
        _exec(address(safe), abi.encodeWithSignature("enableModule(address)", address(rogue)));

        // Phase 1 — the transaction guard is installed, but no module guard. The
        // rogue module signs an unlimited approval down the module path, which the
        // transaction guard never sees, and the wallet is drained.
        bool ok1 = _moduleApproves(ATTACKER_1, type(uint256).max);
        _assertTrue(
            ok1, "phase1: with no module guard, the module path evades the transaction guard"
        );
        _assertEq(
            token.allowance(address(safe), ATTACKER_1),
            type(uint256).max,
            "phase1: attacker got MAX allowance"
        );
        _drain(ATTACKER_1, 5_000e18);
        _assertEq(
            token.balanceOf(ATTACKER_1),
            5_000e18,
            "phase1: attacker drained the wallet down the module path"
        );
        emit Narrate("phase1", "no module guard: rogue module drained 5000 via the module path");

        // Phase 2 — install the module guard. The same attack down the same path
        // is now refused.
        _exec(address(safe), abi.encodeWithSignature("setModuleGuard(address)", address(guard)));
        bool ok2 = _moduleApproves(ATTACKER_2, type(uint256).max);
        _assertTrue(!ok2, "phase2: the module guard must refuse the unlimited approval");
        _assertEq(
            token.allowance(address(safe), ATTACKER_2),
            0,
            "phase2: attacker2 allowance must stay zero"
        );
        _assertTrue(!_tryDrain(ATTACKER_2, 1e18), "phase2: with no allowance the drain must fail");
        emit Narrate("phase2", "module guard installed: the same module-path attack is BLOCKED");
    }

    /// @dev The rogue module approves `spender` for `amount` down the module path;
    /// returns whether it went through (false once the module guard refuses it).
    function _moduleApproves(address spender, uint256 amount) private returns (bool ok) {
        (ok,) = address(rogue).call(
            abi.encodeWithSignature(
                "drain(address,address,address,uint256)",
                address(safe),
                address(token),
                spender,
                amount
            )
        );
    }

    function _drain(address attacker, uint256 amount) private {
        _assertTrue(
            _tryDrain(attacker, amount), "drain should succeed when the attacker holds an allowance"
        );
    }

    function _tryDrain(address attacker, uint256 amount) private returns (bool ok) {
        // The attacker pulls from the Safe using the allowance the rogue module
        // set for it — so the call must come from the attacker itself.
        vm.prank(attacker);
        (ok,) = address(token).call(
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", address(safe), attacker, amount
            )
        );
    }

    function _exec(address to, bytes memory data) private {
        _assertTrue(_tryExec(to, data), "a setup transaction should have succeeded");
    }

    function _tryExec(address to, bytes memory data) private returns (bool ok) {
        uint256 nonce = safe.nonce();
        bytes32 txHash = safe.getTransactionHash(
            to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AGENT_PK, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        (ok,) = address(safe).call(
            abi.encodeWithSelector(
                safe.execTransaction.selector,
                to,
                uint256(0),
                data,
                Enum.Operation.Call,
                uint256(0),
                uint256(0),
                uint256(0),
                address(0),
                payable(address(0)),
                signature
            )
        );
    }

    function _assertTrue(bool condition, string memory message) private pure {
        if (!condition) {
            revert(message);
        }
    }

    function _assertEq(uint256 left, uint256 right, string memory message) private pure {
        if (left != right) {
            revert(message);
        }
    }
}
