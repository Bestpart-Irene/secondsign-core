// SPDX-License-Identifier: Apache-2.0
// DEMO ONLY — a minimal EIP-1967 proxy, so the demo token has the same
// proxy+implementation shape as canonical USDC and the ChainStateReader resolves it.
pragma solidity 0.8.28;

contract DemoProxy {
    bytes32 private constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address implementation) {
        assembly {
            sstore(IMPL_SLOT, implementation)
        }
    }

    fallback() external payable {
        assembly {
            let impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
