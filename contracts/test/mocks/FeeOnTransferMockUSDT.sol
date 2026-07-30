// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// Adversarial 6-decimal fee-on-transfer token. NEVER mainnet.
contract FeeOnTransferMockUSDT is ERC20, ERC20Permit {
    uint256 public feeBps = 100; // 1%

    constructor() ERC20("FeeOnTransfer Mock USDT", "fUSDT") ERC20Permit("FeeOnTransfer Mock USDT") {}

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && feeBps > 0) {
            uint256 fee = (value * feeBps) / 10_000;
            uint256 send = value - fee;
            super._update(from, to, send);
            if (fee > 0) {
                super._update(from, address(0xfee), fee);
            }
            return;
        }
        super._update(from, to, value);
    }
}
