// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";

contract HoldbackEscrowTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    address safe = makeAddr("safe");
    address vault = makeAddr("vault");
    address reserve = makeAddr("reserve");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    bytes32 constant JOB = keccak256("job-1");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        vm.startPrank(safe);
        escrow.setVault(vault);
        goat.setMinter(vault, true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(reserve, true);
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setEnrolled(bob, true, bytes32(0));
        vm.stopPrank();
    }

    /// Vault mints holdback GOAT to escrow then credits it.
    function _creditViaVault(address worker, uint256 amount) internal {
        vm.startPrank(vault);
        goat.mint(address(escrow), amount);
        escrow.credit(JOB, worker, amount, uint64(block.timestamp + 30 days));
        vm.stopPrank();
    }

    function test_only_vault_can_credit() public {
        vm.expectRevert(HoldbackEscrow.NotVault.selector);
        vm.prank(alice);
        escrow.credit(JOB, alice, 1e18, uint64(block.timestamp + 30 days));
    }

    function test_release_pays_all_workers() public {
        _creditViaVault(alice, 15e18);
        _creditViaVault(bob, 30e18);
        vm.prank(safe);
        escrow.release(JOB);
        assertEq(goat.balanceOf(alice), 15e18);
        assertEq(goat.balanceOf(bob), 30e18);
        assertTrue(escrow.jobReleased(JOB));
    }

    function test_slash_goes_to_reserve_never_burn() public {
        _creditViaVault(alice, 15e18);
        vm.prank(safe);
        escrow.slash(JOB, alice, 10e18, keccak256("fabricated shards"));
        assertEq(goat.balanceOf(reserve), 10e18);
        assertEq(escrow.holdbackOf(JOB, alice), 5e18);
        // remaining still releasable
        vm.prank(safe);
        escrow.release(JOB);
        assertEq(goat.balanceOf(alice), 5e18);
    }

    function test_backstop_release_by_anyone_after_deadline() public {
        _creditViaVault(alice, 15e18);
        vm.expectRevert(HoldbackEscrow.DeadlineNotReached.selector);
        escrow.releaseAfterDeadline(JOB);

        vm.warp(block.timestamp + 30 days + 1);
        vm.prank(makeAddr("anyone"));
        escrow.releaseAfterDeadline(JOB);
        assertEq(goat.balanceOf(alice), 15e18);
    }

    function test_no_double_release() public {
        _creditViaVault(alice, 15e18);
        vm.prank(safe);
        escrow.release(JOB);
        vm.expectRevert(HoldbackEscrow.AlreadyReleased.selector);
        vm.prank(safe);
        escrow.release(JOB);
    }

    function test_release_before_credit_reverts() public {
        bytes32 emptyJob = keccak256("never-credited");
        vm.warp(block.timestamp + 31 days);
        vm.expectRevert(HoldbackEscrow.NothingCredited.selector);
        escrow.releaseAfterDeadline(emptyJob);
        vm.expectRevert(HoldbackEscrow.NothingCredited.selector);
        vm.prank(safe);
        escrow.release(emptyJob);
    }

    function test_credit_and_slash_after_release_revert() public {
        _creditViaVault(alice, 15e18);
        vm.prank(safe);
        escrow.release(JOB);
        vm.startPrank(vault);
        goat.mint(address(escrow), 1e18);
        vm.expectRevert(HoldbackEscrow.AlreadyReleased.selector);
        escrow.credit(JOB, alice, 1e18, uint64(block.timestamp + 30 days));
        vm.stopPrank();
        vm.expectRevert(HoldbackEscrow.AlreadyReleased.selector);
        vm.prank(safe);
        escrow.slash(JOB, alice, 1e18, keccak256("late"));
    }

    function test_deadline_never_shrinks() public {
        vm.startPrank(vault);
        goat.mint(address(escrow), 2e18);
        escrow.credit(JOB, alice, 1e18, uint64(block.timestamp + 30 days));
        uint64 d1 = escrow.jobDeadline(JOB);
        escrow.credit(JOB, alice, 1e18, uint64(block.timestamp + 10 days));
        vm.stopPrank();
        assertEq(escrow.jobDeadline(JOB), d1);
    }

    function test_no_duplicate_worker_entries_after_full_slash() public {
        _creditViaVault(alice, 10e18);
        vm.prank(safe);
        escrow.slash(JOB, alice, 10e18, keccak256("bad"));
        _creditViaVault(alice, 5e18);
        vm.prank(safe);
        escrow.release(JOB);
        assertEq(goat.balanceOf(alice), 5e18);
    }
}
