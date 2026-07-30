// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";

interface IReenterTarget {
    function reenter() external;
}

/// Adversarial token that attempts reentrancy during transferFrom.
/// NEVER mainnet.
contract ReenteringMockUSDT is ERC20, ERC20Permit {
    address public target;
    bool public armed;

    constructor() ERC20("Reentering Mock USDT", "rUSDT") ERC20Permit("Reentering Mock USDT") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function arm(address target_) external {
        target = target_;
        armed = true;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (armed && from != address(0) && to != address(0) && target != address(0)) {
            armed = false;
            IReenterTarget(target).reenter();
        }
        super._update(from, to, value);
    }
}
