// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {GoatCoin} from "./GoatCoin.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";
import {BuyDesk} from "./BuyDesk.sol";

/// Donor BuyDesk Factory (design 2026-07-13): "any worker becomes a donor
/// anytime, from their existing wallet." A BuyDesk's `owner` receives the
/// GOAT sold to it, so the owner only needs to be enrolled — and every
/// worker already is. Calling `createDesk` deploys a `BuyDesk` owned by
/// the CALLER's existing wallet: same wallet, both roles, no new wallet,
/// zero extra founder approval for worker-owners. A pure donor (never a
/// worker) still needs the founder to `setEnrolled` them once before
/// their desk accepts sells (BuyDesk's own DEPLOY PRECONDITION) — this
/// factory has no registry powers and cannot enroll anyone.
///
/// `BuyDesk.sol` is reused UNCHANGED; this factory only constructs
/// instances and indexes them. One desk per owner in v1 — keeps "your
/// desk" unambiguous; a second `createDesk` call from the same caller
/// reverts `AlreadyHasDesk`.
contract BuyDeskFactory {
    error AlreadyHasDesk();
    error ZeroAddress();
    error NoDesk();

    IERC20 public immutable usdt;
    GoatCoin public immutable goat;
    EnrollmentRegistry public immutable registry;

    address[] public desks;
    mapping(address => address) public deskOf; // owner => desk (one per owner, v1)
    mapping(address => string) public nameOf; // owner => display name

    event DeskCreated(address indexed owner, address indexed desk, uint256 index);
    event DeskNamed(address indexed owner, address indexed desk, string name);

    constructor(IERC20 usdt_, GoatCoin goat_, EnrollmentRegistry registry_) {
        if (address(usdt_) == address(0)) revert ZeroAddress();
        if (address(goat_) == address(0)) revert ZeroAddress();
        if (address(registry_) == address(0)) revert ZeroAddress();
        usdt = usdt_;
        goat = goat_;
        registry = registry_;
    }

    /// One-click "become a donor" — deploys a BuyDesk owned by the
    /// CALLER's existing wallet, with an owner-chosen display NAME.
    /// Reverts if the caller already has one.
    function createDesk(string calldata name) external returns (address desk) {
        if (deskOf[msg.sender] != address(0)) revert AlreadyHasDesk();
        desk = address(new BuyDesk(msg.sender, usdt, goat, registry));
        deskOf[msg.sender] = desk;
        desks.push(desk);
        emit DeskCreated(msg.sender, desk, desks.length - 1);
        nameOf[msg.sender] = name;
        emit DeskNamed(msg.sender, desk, name);
    }

    /// Owner renames their desk anytime.
    function setDeskName(string calldata name) external {
        if (deskOf[msg.sender] == address(0)) revert NoDesk();
        nameOf[msg.sender] = name;
        emit DeskNamed(msg.sender, deskOf[msg.sender], name);
    }

    function desksLength() external view returns (uint256) {
        return desks.length;
    }
}
