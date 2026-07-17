// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {WorkMinter} from "../src/WorkMinter.sol";

contract WorkMinterTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    WorkMinter minter;
    address safe = makeAddr("safe");
    address reserve = makeAddr("reserve");
    address acceptor = makeAddr("acceptor");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    bytes32 constant JOB = keccak256("free-market-job-1");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        // Constructor takes exactly (safe, goat, escrow) — no USDT anywhere
        // on the free-market mint path (spec §2, task S1). If WorkMinter
        // required an IERC20 here, this line would fail to compile.
        minter = new WorkMinter(safe, goat, escrow);
        vm.startPrank(safe);
        escrow.setVault(address(minter));
        goat.setMinter(address(minter), true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(address(minter), true);
        reg.setSystemAddress(reserve, true);
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setEnrolled(bob, true, bytes32(0));
        vm.stopPrank();
    }

    function _createJob() internal {
        vm.prank(safe);
        minter.createJob(JOB, keccak256("catalog-entry"), 1e18, 1500, acceptor, false);
    }

    function _job(bytes32 jobId)
        internal
        view
        returns (
            bytes32 catalogHash,
            uint256 unitReward,
            uint256 minted,
            uint16 holdbackBps,
            address externalAcceptor,
            bool founderAcceptOnly,
            bool closed,
            uint64 lastMint
        )
    {
        return minter.jobs(jobId);
    }

    // --- auth: only-safe on all three entry points ---

    function test_createJob_onlySafe() public {
        vm.expectRevert(WorkMinter.NotSafe.selector);
        minter.createJob(JOB, keccak256("catalog-entry"), 1e18, 1500, acceptor, false);
    }

    function test_mintBatch_onlySafe() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        units[0] = 10;
        vm.expectRevert(WorkMinter.NotSafe.selector);
        minter.mintBatch(JOB, keccak256("manifest-1"), workers, units);
    }

    function test_closeJob_onlySafe() public {
        _createJob();
        vm.expectRevert(WorkMinter.NotSafe.selector);
        minter.closeJob(JOB);
    }

    // --- createJob ---

    function test_founderAcceptOnly_required_without_acceptor() public {
        vm.expectRevert(WorkMinter.FounderAcceptRequired.selector);
        vm.prank(safe);
        minter.createJob(JOB, keccak256("catalog-entry"), 1e18, 1500, address(0), false);
        // with founderAcceptOnly=true and no external acceptor, it succeeds
        vm.prank(safe);
        minter.createJob(JOB, keccak256("catalog-entry"), 1e18, 1500, address(0), true);
    }

    function test_createJob_rejects_invalid_holdback() public {
        vm.expectRevert(WorkMinter.InvalidHoldback.selector);
        vm.prank(safe);
        minter.createJob(JOB, keccak256("catalog-entry"), 1e18, 10_001, acceptor, false);
    }

    function test_createJob_rejects_zero_unitReward() public {
        vm.expectRevert(WorkMinter.InvalidUnitReward.selector);
        vm.prank(safe);
        minter.createJob(JOB, keccak256("catalog-entry"), 0, 1500, acceptor, false);
    }

    function test_createJob_rejects_duplicate() public {
        _createJob();
        vm.expectRevert(WorkMinter.JobExists.selector);
        vm.prank(safe);
        minter.createJob(JOB, keccak256("catalog-entry"), 1e18, 1500, acceptor, false);
    }

    function test_createJob_stores_fields_in_view_order() public {
        _createJob();
        (
            bytes32 catalogHash,
            uint256 unitReward,
            uint256 minted,
            uint16 holdbackBps,
            address externalAcceptor,
            bool founderAcceptOnly,
            bool closed,
            uint64 lastMint
        ) = _job(JOB);
        assertEq(catalogHash, keccak256("catalog-entry"));
        assertEq(unitReward, 1e18);
        assertEq(minted, 0);
        assertEq(holdbackBps, 1500);
        assertEq(externalAcceptor, acceptor);
        assertEq(founderAcceptOnly, false);
        assertEq(closed, false);
        assertEq(lastMint, 0);
    }

    // --- mintBatch: unit -> GOAT math, 85/15 reconciliation, no USDT ---

    function test_mintBatch_unit_math_and_holdback_reconciliation() public {
        _createJob();
        address[] memory workers = new address[](2);
        uint256[] memory units = new uint256[](2);
        workers[0] = alice; // 10 units * 1 GOAT/unit = 10 GOAT
        units[0] = 10;
        workers[1] = bob; // 20 units * 1 GOAT/unit = 20 GOAT
        units[1] = 20;
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("manifest-1"), workers, units);

        assertEq(goat.balanceOf(alice), 8.5e18); // 85% liquid
        assertEq(escrow.holdbackOf(JOB, alice), 1.5e18); // 15% holdback
        assertEq(goat.balanceOf(bob), 17e18);
        assertEq(escrow.holdbackOf(JOB, bob), 3e18);
        // liquid + holdback == units * unitReward exactly (no USDT budget
        // cap, no desk transfer — free-market mint law).
        assertEq(goat.totalSupply(), 30e18);
        (,, uint256 minted,,,,,) = _job(JOB);
        assertEq(minted, 30e18);
    }

    function test_mintBatch_respects_per_job_unitReward() public {
        vm.prank(safe);
        minter.createJob(JOB, keccak256("catalog-entry"), 2e18, 0, acceptor, false);
        address[] memory workers = new address[](1);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        units[0] = 5; // 5 units * 2 GOAT/unit = 10 GOAT, 0 holdback
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("manifest-1"), workers, units);
        assertEq(goat.balanceOf(alice), 10e18);
        assertEq(escrow.holdbackOf(JOB, alice), 0);
    }

    function test_mintBatch_on_unknown_job_reverts() public {
        address[] memory workers = new address[](1);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        units[0] = 1;
        vm.expectRevert(WorkMinter.JobUnknown.selector);
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("manifest-1"), workers, units);
    }

    function test_mintBatch_on_closed_job_reverts() public {
        _createJob();
        vm.prank(safe);
        minter.closeJob(JOB); // nothing minted yet -> closes cleanly
        address[] memory workers = new address[](1);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        units[0] = 1;
        vm.expectRevert(WorkMinter.JobClosed.selector);
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("manifest-1"), workers, units);
    }

    function test_mintBatch_rejects_replayed_manifestRoot() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        units[0] = 10;
        bytes32 root = keccak256("manifest-1");
        vm.prank(safe);
        minter.mintBatch(JOB, root, workers, units);

        // Identical manifestRoot again reverts, even with the same job/inputs.
        vm.expectRevert(WorkMinter.ManifestReplayed.selector);
        vm.prank(safe);
        minter.mintBatch(JOB, root, workers, units);

        // A different root mints fine.
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("manifest-2"), workers, units);
        assertEq(goat.balanceOf(alice), 17e18); // 2x 8.5 GOAT liquid
    }

    function test_mintBatch_length_mismatch_reverts() public {
        _createJob();
        address[] memory workers = new address[](2);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        workers[1] = bob;
        units[0] = 1;
        vm.expectRevert(WorkMinter.LengthMismatch.selector);
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("manifest-1"), workers, units);
    }

    function test_mintBatch_sets_holdback_deadline_30_days() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        units[0] = 10;
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("m"), workers, units);
        assertEq(escrow.jobDeadline(JOB), block.timestamp + 30 days);
    }

    // --- closeJob: holdback gating ---

    function test_closeJob_requires_holdback_settlement() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory units = new uint256[](1);
        workers[0] = alice;
        units[0] = 10;
        vm.prank(safe);
        minter.mintBatch(JOB, keccak256("m"), workers, units);

        vm.expectRevert(WorkMinter.HoldbackOpen.selector);
        vm.prank(safe);
        minter.closeJob(JOB);

        vm.prank(safe);
        escrow.release(JOB);
        vm.prank(safe);
        minter.closeJob(JOB);
        (,,,,,, bool closed,) = _job(JOB);
        assertTrue(closed);
    }

    function test_closeJob_allows_when_nothing_minted() public {
        _createJob();
        vm.prank(safe);
        minter.closeJob(JOB);
        (,,,,,, bool closed,) = _job(JOB);
        assertTrue(closed);
    }

    function test_closeJob_on_unknown_job_reverts() public {
        vm.expectRevert(WorkMinter.JobUnknown.selector);
        vm.prank(safe);
        minter.closeJob(JOB);
    }

    function test_closeJob_already_closed_reverts() public {
        _createJob();
        vm.prank(safe);
        minter.closeJob(JOB);
        vm.expectRevert(WorkMinter.JobClosed.selector);
        vm.prank(safe);
        minter.closeJob(JOB);
    }
}
