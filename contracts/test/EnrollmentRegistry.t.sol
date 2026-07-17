// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";

contract EnrollmentRegistryTest is Test {
    EnrollmentRegistry reg;
    address safe = makeAddr("safe");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address desk = makeAddr("desk");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
    }

    function test_safe_can_enroll_and_events_fire() public {
        vm.prank(safe);
        reg.setEnrolled(alice, true, keccak256("kyc-alice"));
        assertTrue(reg.enrolled(alice));
    }

    function test_non_safe_cannot_enroll() public {
        vm.expectRevert(EnrollmentRegistry.NotSafe.selector);
        vm.prank(alice);
        reg.setEnrolled(alice, true, bytes32(0));
    }

    function test_transfer_allowed_only_between_enrolled() public {
        vm.startPrank(safe);
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setEnrolled(bob, true, bytes32(0));
        vm.stopPrank();
        assertTrue(reg.isTransferAllowed(alice, bob));
        assertFalse(reg.isTransferAllowed(alice, makeAddr("stranger")));
    }

    function test_system_address_bypasses_enrollment() public {
        vm.startPrank(safe);
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setSystemAddress(desk, true);
        vm.stopPrank();
        assertTrue(reg.isTransferAllowed(alice, desk));
        assertTrue(reg.isTransferAllowed(desk, makeAddr("stranger")));
    }

    function test_unenroll_revokes() public {
        vm.startPrank(safe);
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setEnrolled(bob, true, bytes32(0));
        reg.setEnrolled(bob, false, bytes32(0));
        vm.stopPrank();
        assertFalse(reg.isTransferAllowed(alice, bob));
    }

    function test_non_safe_cannot_set_system_address() public {
        vm.expectRevert(EnrollmentRegistry.NotSafe.selector);
        vm.prank(alice);
        reg.setSystemAddress(desk, true);
    }

    function test_events_emit_exact_args() public {
        vm.expectEmit(true, false, false, true);
        emit EnrollmentRegistry.Enrolled(alice, true, keccak256("kyc-alice"));
        vm.prank(safe);
        reg.setEnrolled(alice, true, keccak256("kyc-alice"));

        vm.expectEmit(true, false, false, true);
        emit EnrollmentRegistry.SystemAddressSet(desk, true);
        vm.prank(safe);
        reg.setSystemAddress(desk, true);
    }

    function test_kycref_stored() public {
        vm.prank(safe);
        reg.setEnrolled(alice, true, keccak256("kyc-alice"));
        assertEq(reg.kycRef(alice), keccak256("kyc-alice"));
    }
}
