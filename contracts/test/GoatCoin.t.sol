// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";

contract GoatCoinTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    address safe = makeAddr("safe");
    address vault = makeAddr("vault");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address stranger = makeAddr("stranger");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        vm.startPrank(safe);
        goat.setMinter(vault, true);
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setEnrolled(bob, true, bytes32(0));
        vm.stopPrank();
    }

    function test_only_minter_can_mint() public {
        vm.prank(vault);
        goat.mint(alice, 100e18);
        assertEq(goat.balanceOf(alice), 100e18);

        vm.expectRevert(GoatCoin.NotMinter.selector);
        vm.prank(stranger);
        goat.mint(stranger, 1e18);
    }

    function test_enrolled_can_transfer_stranger_cannot() public {
        vm.prank(vault);
        goat.mint(alice, 100e18);

        vm.prank(alice);
        goat.transfer(bob, 40e18);
        assertEq(goat.balanceOf(bob), 40e18);

        vm.expectRevert(GoatCoin.TransferRestricted.selector);
        vm.prank(alice);
        goat.transfer(stranger, 1e18);
    }

    function test_lift_restriction_is_one_way_and_opens_transfers() public {
        vm.prank(vault);
        goat.mint(alice, 100e18);

        vm.prank(safe);
        goat.liftRestriction();
        assertFalse(goat.restricted());

        vm.prank(alice);
        goat.transfer(stranger, 1e18); // now allowed
        assertEq(goat.balanceOf(stranger), 1e18);
    }

    function test_pause_blocks_transfers() public {
        vm.prank(vault);
        goat.mint(alice, 100e18);
        vm.prank(safe);
        goat.pause();
        vm.expectRevert(); // EnforcedPause
        vm.prank(alice);
        goat.transfer(bob, 1e18);
    }

    function test_non_safe_cannot_admin() public {
        vm.expectRevert(GoatCoin.NotSafe.selector);
        vm.prank(alice);
        goat.liftRestriction();
        vm.expectRevert(GoatCoin.NotSafe.selector);
        vm.prank(alice);
        goat.setMinter(alice, true);
    }

    function test_mint_blocked_while_paused() public {
        vm.prank(safe);
        goat.pause();
        vm.expectRevert(); // OZ EnforcedPause
        vm.prank(vault);
        goat.mint(alice, 1e18);
    }

    function test_mint_to_unenrolled_recipient_while_restricted() public {
        vm.prank(vault);
        goat.mint(stranger, 5e18);
        assertEq(goat.balanceOf(stranger), 5e18);
    }

    function test_non_safe_cannot_pause_or_unpause() public {
        vm.expectRevert(GoatCoin.NotSafe.selector);
        vm.prank(alice);
        goat.pause();
        vm.prank(safe);
        goat.pause();
        vm.expectRevert(GoatCoin.NotSafe.selector);
        vm.prank(alice);
        goat.unpause();
    }

    function test_permit_happy_path() public {
        uint256 ownerKey = 0xA11CE;
        address owner = vm.addr(ownerKey);
        vm.prank(safe);
        reg.setEnrolled(owner, true, bytes32(0));
        vm.prank(vault);
        goat.mint(owner, 10e18);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner,
                bob,
                3e18,
                goat.nonces(owner),
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", goat.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);
        goat.permit(owner, bob, 3e18, deadline, v, r, s);
        assertEq(goat.allowance(owner, bob), 3e18);
    }
}
