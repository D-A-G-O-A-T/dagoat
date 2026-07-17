// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {RedemptionDesk} from "../src/RedemptionDesk.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract RedemptionDeskTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    RedemptionDesk desk;
    MockUSDT usdt;
    address safe = makeAddr("safe");
    address founder = makeAddr("founder"); // Season 0 beneficiary
    address minter = makeAddr("minter");
    address alice = makeAddr("alice");
    address stranger = makeAddr("stranger");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        usdt = new MockUSDT();
        desk = new RedemptionDesk(safe, IERC20(address(usdt)), goat, reg, founder);
        vm.startPrank(safe);
        goat.setMinter(minter, true);
        reg.setSystemAddress(address(desk), true);
        reg.setSystemAddress(founder, true);
        reg.setEnrolled(alice, true, bytes32(0));
        vm.stopPrank();
        // alice earned 1000 GOAT; desk holds its backing (10 USDT)
        vm.prank(minter);
        goat.mint(alice, 1000e18);
        usdt.mint(address(desk), 10e6);
        vm.prank(alice);
        goat.approve(address(desk), type(uint256).max);
    }

    function _openWindow(uint256 cap) internal {
        vm.prank(safe);
        desk.openWindow(uint64(block.timestamp), uint64(block.timestamp + 1 days), cap);
    }

    function test_redeem_swaps_goat_for_usdt_atomically() public {
        _openWindow(1000e18);
        vm.prank(alice);
        desk.redeem(600e18);
        assertEq(usdt.balanceOf(alice), 6e6); // 600 GOAT * 0.01
        assertEq(goat.balanceOf(founder), 600e18); // founder acquires & holds
        assertEq(goat.balanceOf(alice), 400e18);
    }

    function test_redeem_requires_open_window() public {
        vm.expectRevert(RedemptionDesk.NoActiveWindow.selector);
        vm.prank(alice);
        desk.redeem(1e18);
    }

    function test_redeem_respects_per_account_cap() public {
        _openWindow(500e18);
        vm.prank(alice);
        desk.redeem(500e18);
        vm.expectRevert(RedemptionDesk.CapExceeded.selector);
        vm.prank(alice);
        desk.redeem(1e18);
    }

    function test_redeem_requires_enrollment() public {
        _openWindow(1000e18);
        vm.expectRevert(RedemptionDesk.NotEnrolled.selector);
        vm.prank(stranger);
        desk.redeem(1e18);
    }

    function test_window_expires() public {
        _openWindow(1000e18);
        vm.warp(block.timestamp + 1 days + 1);
        vm.expectRevert(RedemptionDesk.NoActiveWindow.selector);
        vm.prank(alice);
        desk.redeem(1e18);
    }

    function test_beneficiary_cannot_redeem() public {
        _openWindow(1000e18);
        vm.startPrank(safe);
        reg.setEnrolled(founder, true, bytes32(0));
        vm.stopPrank();
        vm.prank(minter);
        goat.mint(founder, 10e18);
        vm.prank(founder);
        goat.approve(address(desk), type(uint256).max);
        vm.expectRevert(RedemptionDesk.BeneficiaryCannotRedeem.selector);
        vm.prank(founder);
        desk.redeem(1e18);
    }

    function test_redeem_zero_or_dust_reverts() public {
        _openWindow(1000e18);
        vm.expectRevert(RedemptionDesk.ZeroPayout.selector);
        vm.prank(alice);
        desk.redeem(0);
        vm.expectRevert(RedemptionDesk.ZeroPayout.selector);
        vm.prank(alice);
        desk.redeem(1e14 - 1); // floors to 0 USDT
        // smallest redeemable unit still works: 1e14 GOAT wei = 1 micro-USDT
        vm.prank(alice);
        desk.redeem(1e14);
        assertEq(usdt.balanceOf(alice), 1);
    }
}
