// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SecondSign contributors
pragma solidity 0.8.28;

import {Safe} from "safe-1.5.0/contracts/Safe.sol";
import {SafeProxy} from "safe-1.5.0/contracts/proxies/SafeProxy.sol";
import {Enum} from "safe-1.5.0/contracts/libraries/Enum.sol";
import {BaseTransactionGuard} from "safe-1.5.0/contracts/base/GuardManager.sol";

/// @notice DEMO ONLY — a runnable illustration, NOT the production guard and NOT
/// the ONCHAIN-S001 topology proof.
///
/// The on-chain threat that has no fiat analogue is the token *approval*: an
/// agent that signs `approve(spender, 2^256-1)` has handed someone the keys to
/// the vault (`C-RT-001` in the on-chain threat model). A per-transaction amount
/// cap on value transfers — the fiat instinct — never sees it, because no value
/// moves at approval time; the drain happens later, from the spender's side.
///
/// This file stands up a real Safe 1.5.0, gives it a token, installs a minimal
/// transaction guard, and shows three things in one run:
///
///   1. a bounded approval to a known counterparty is allowed;
///   2. `approve(attacker, type(uint256).max)` is refused by the guard — and so
///      the attacker's later `transferFrom` pulls nothing;
///   3. the agent cannot remove its own guard to clear the way.
///
/// The guard here is deliberately minimal (one cap, one self-neutralise rule).
/// The production guard, its full effect model, and the *module* guard — the
/// second half of the double guard, which closes the 1.4.1 module-path bypass —
/// are later slices. `src/` stays empty on purpose (see `foundry.toml`); this
/// lives under `test/` and ships nothing.
///
/// Run it:  forge test --match-path 'test/demo/DoubleGuardDemo.t.sol' -vvv

/// @dev Minimal cheatcode access — this workspace carries no forge-std.
interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        pure
        returns (uint8 v, bytes32 r, bytes32 s);
    function load(address target, bytes32 slot) external view returns (bytes32);
}

/// @dev A minimal ERC-20 the Safe holds. Enough to approve, transfer, and be drained.
contract DemoToken {
    string public name = "Demo USD";
    string public symbol = "dUSD";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount; // underflows (reverts) without allowance
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

/// @dev The illustrative guard: refuse an over-cap ERC-20 approval, and refuse
/// the account's attempt to change its own guard.
contract DemoApprovalGuard is BaseTransactionGuard {
    address public immutable token;
    uint256 public immutable approvalCap;

    bytes4 private constant APPROVE = bytes4(keccak256("approve(address,uint256)"));
    bytes4 private constant SET_GUARD = bytes4(keccak256("setGuard(address)"));

    constructor(address token_, uint256 approvalCap_) {
        token = token_;
        approvalCap = approvalCap_;
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
        if (data.length < 4) {
            return;
        }
        bytes4 selector;
        assembly {
            selector := mload(add(data, 0x20))
        }
        // The approval drain vector: an allowance above the cap is refused
        // whatever the spender, because the danger is the allowance, not a move.
        if (to == token && selector == APPROVE && data.length >= 0x44) {
            uint256 amount;
            assembly {
                amount := mload(add(data, 0x44))
            }
            require(amount <= approvalCap, "SecondSign demo: approval over cap");
        }
        // A self-authorised call (to == the Safe calling this guard) that would
        // change the guard is refused: the account cannot disarm itself.
        if (to == msg.sender && selector == SET_GUARD) {
            revert("SecondSign demo: cannot remove its own guard");
        }
    }

    function checkAfterExecution(bytes32, bool) external override {}
}

contract DoubleGuardDemoTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    // Safe's guard storage slot (keccak256("guard_manager.guard.address")).
    bytes32 private constant GUARD_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    uint256 private constant AGENT_PK = 0xA11CE;
    uint256 private constant APPROVAL_CAP = 1_000e18;

    event Narrate(string act, string outcome);

    Safe private safe;
    DemoToken private token;
    DemoApprovalGuard private guard;
    address private agent;
    address private constant COUNTERPARTY = address(0xC0FFEE);
    address private constant ATTACKER = address(0xBAD);

    function test_theDoubleGuardStopsARogueAgent() public {
        agent = vm.addr(AGENT_PK);

        // A real Safe 1.5.0 account: a proxy over the singleton (the singleton
        // itself is deployed unusable, threshold 1, so it can only back proxies).
        Safe singleton = new Safe();
        safe = Safe(payable(address(new SafeProxy(address(singleton)))));
        address[] memory owners = new address[](1);
        owners[0] = agent;
        safe.setup(owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)));

        // A token the Safe holds, and the guard that will watch it.
        token = new DemoToken();
        token.mint(address(safe), 10_000e18);
        guard = new DemoApprovalGuard(address(token), APPROVAL_CAP);

        // Install the guard. No guard is watching yet, so this self-call goes through.
        _exec(address(safe), abi.encodeWithSignature("setGuard(address)", address(guard)));
        _assertEq(_installedGuard(), address(guard), "guard should be installed");

        // Act 1 — a bounded approval to a known counterparty is allowed.
        bool ok1 = _tryExec(
            address(token),
            abi.encodeWithSignature("approve(address,uint256)", COUNTERPARTY, uint256(100e18))
        );
        _assertTrue(ok1, "act1: a bounded approval must be allowed");
        _assertEq(
            token.allowance(address(safe), COUNTERPARTY), 100e18, "act1: allowance must be set"
        );
        emit Narrate("act1", "approve(counterparty, 100) ALLOWED");

        // Act 2 — an unlimited approval to an attacker is refused, so the
        // attacker's later transferFrom pulls nothing.
        bool ok2 = _tryExec(
            address(token),
            abi.encodeWithSignature("approve(address,uint256)", ATTACKER, type(uint256).max)
        );
        _assertTrue(!ok2, "act2: an unlimited approval must be blocked");
        _assertEq(
            token.allowance(address(safe), ATTACKER), 0, "act2: attacker allowance must stay zero"
        );
        bool pulled = _attackerPulls(1e18);
        _assertTrue(!pulled, "act2: with no allowance the drain must fail");
        _assertEq(token.balanceOf(ATTACKER), 0, "act2: attacker must hold nothing");
        emit Narrate("act2", "approve(attacker, MAX) BLOCKED; attacker drains nothing");

        // Act 3 — the agent cannot remove its own guard to clear the way.
        bool ok3 = _tryExec(address(safe), abi.encodeWithSignature("setGuard(address)", address(0)));
        _assertTrue(!ok3, "act3: removing the guard must be blocked");
        _assertEq(_installedGuard(), address(guard), "act3: the guard must still be installed");
        emit Narrate("act3", "setGuard(0) BLOCKED; the agent cannot disarm itself");
    }

    /// @dev Build, sign and execute a Safe transaction from the agent; require success.
    function _exec(address to, bytes memory data) private {
        _assertTrue(_tryExec(to, data), "a setup transaction should have succeeded");
    }

    /// @dev Build, sign and execute; return whether execTransaction succeeded. A
    /// guard revert surfaces as `false` rather than bubbling out of the test.
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

    function _attackerPulls(uint256 amount) private returns (bool ok) {
        (ok,) = address(token).call(
            abi.encodeWithSignature(
                "transferFrom(address,address,uint256)", address(safe), ATTACKER, amount
            )
        );
    }

    function _installedGuard() private view returns (address) {
        return address(uint160(uint256(vm.load(address(safe), GUARD_SLOT))));
    }

    function _assertTrue(bool condition, string memory message) private pure {
        if (!condition) {
            revert(message);
        }
    }

    function _assertEq(address left, address right, string memory message) private pure {
        if (left != right) {
            revert(message);
        }
    }

    function _assertEq(uint256 left, uint256 right, string memory message) private pure {
        if (left != right) {
            revert(message);
        }
    }
}
