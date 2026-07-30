// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// Test-only 6-decimal USDT stand-in with EIP-2612 permit. NEVER mainnet.
contract PermitMockUSDT is ERC20, ERC20Permit {
    constructor() ERC20("Permit Mock USDT", "pUSDT") ERC20Permit("Permit Mock USDT") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
