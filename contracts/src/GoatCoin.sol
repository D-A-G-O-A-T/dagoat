// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20Pausable} from "openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";

/// GoatCoin (spec §2.2): ERC-20 + permit + pausable. While `restricted`,
/// transfers require EnrollmentRegistry approval (mint/burn exempt).
/// Minters are JobVault instances only — there is no other mint path.
/// Pause is the S5 incident-response control: an honest pilot-phase
/// centralized power, documented, removed with progressive sovereignty.
contract GoatCoin is ERC20, ERC20Permit, ERC20Pausable {
    error NotSafe();
    error NotMinter();
    error TransferRestricted();

    address public immutable safe;
    EnrollmentRegistry public immutable registry;
    mapping(address => bool) public isMinter;
    bool public restricted = true;

    event MinterSet(address indexed who, bool status);
    event RestrictionLifted();

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(string memory name_, string memory symbol_, address safe_, EnrollmentRegistry registry_)
        ERC20(name_, symbol_)
        ERC20Permit(name_)
    {
        safe = safe_;
        registry = registry_;
    }

    function setMinter(address who, bool status) external onlySafe {
        isMinter[who] = status;
        emit MinterSet(who, status);
    }

    function mint(address to, uint256 amount) external {
        if (!isMinter[msg.sender]) revert NotMinter();
        _mint(to, amount);
    }

    /// One-way: reserved for listing readiness (P5). No un-lift exists.
    function liftRestriction() external onlySafe {
        restricted = false;
        emit RestrictionLifted();
    }

    function pause() external onlySafe {
        _pause();
    }

    function unpause() external onlySafe {
        _unpause();
    }

    function _update(address from, address to, uint256 value) internal override(ERC20, ERC20Pausable) {
        if (restricted && from != address(0) && to != address(0)) {
            if (!registry.isTransferAllowed(from, to)) revert TransferRestricted();
        }
        super._update(from, to, value);
    }
}
