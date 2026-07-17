// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {JobVault} from "../src/JobVault.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract JobVaultTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    JobVault vault;
    MockUSDT usdt;
    address safe = makeAddr("safe");
    address founder = makeAddr("founder");
    address desk = makeAddr("desk");
    address reserve = makeAddr("reserve");
    address acceptor = makeAddr("acceptor");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    bytes32 constant JOB = keccak256("pilot-job-1");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        usdt = new MockUSDT();
        vault = new JobVault(safe, IERC20(address(usdt)), goat, escrow, desk);
        vm.startPrank(safe);
        escrow.setVault(address(vault));
        goat.setMinter(address(vault), true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(address(vault), true);
        reg.setSystemAddress(desk, true);
        reg.setSystemAddress(reserve, true);
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setEnrolled(bob, true, bytes32(0));
        vm.stopPrank();
        // founder pilot: $850 contributor pool (6dp)
        usdt.mint(founder, 850e6);
        vm.prank(founder);
        usdt.approve(address(vault), type(uint256).max);
    }

    function _createJob() internal {
        vm.prank(safe);
        vault.createJob(JOB, keccak256("catalog-entry"), founder, 850e6, 1500, acceptor, false);
    }

    function test_createJob_pulls_escrow_from_funder() public {
        _createJob();
        assertEq(usdt.balanceOf(address(vault)), 850e6);
        assertEq(usdt.balanceOf(founder), 0);
    }

    function test_rehearsal_flag_required_without_acceptor() public {
        vm.expectRevert(JobVault.RehearsalRequired.selector);
        vm.prank(safe);
        vault.createJob(JOB, keccak256("catalog-entry"), founder, 850e6, 1500, address(0), false);
        // with rehearsal=true it succeeds
        vm.prank(safe);
        vault.createJob(JOB, keccak256("catalog-entry"), founder, 850e6, 1500, address(0), true);
    }

    function test_mintBatch_splits_liquid_and_holdback_and_funds_desk() public {
        _createJob();
        address[] memory workers = new address[](2);
        uint256[] memory amounts = new uint256[](2);
        workers[0] = alice; // 1000 GOAT = 10 USDT
        amounts[0] = 1000e18;
        workers[1] = bob; // 2000 GOAT = 20 USDT
        amounts[1] = 2000e18;
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("manifest-1"), workers, amounts);

        assertEq(goat.balanceOf(alice), 850e18); // 85% liquid
        assertEq(escrow.holdbackOf(JOB, alice), 150e18); // 15% holdback
        assertEq(goat.balanceOf(bob), 1700e18);
        assertEq(escrow.holdbackOf(JOB, bob), 300e18);
        // liquid + holdback == minted (amendment 2 reconciliation)
        assertEq(goat.totalSupply(), 3000e18);
        // USDT backing moved to desk: 3000 GOAT * 0.01 = 30 USDT
        assertEq(usdt.balanceOf(desk), 30e6);
        assertEq(usdt.balanceOf(address(vault)), 820e6);
    }

    function test_mint_cannot_outrun_escrow() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        workers[0] = alice;
        amounts[0] = 85_001e18; // 85,001 GOAT = 850.01 USDT > 850 budget
        vm.expectRevert(JobVault.MintExceedsEscrow.selector);
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("manifest-1"), workers, amounts);
        // exactly the budget is fine
        amounts[0] = 85_000e18;
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("manifest-1"), workers, amounts);
    }

    function test_closeJob_refunds_unminted_remainder() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        workers[0] = alice;
        amounts[0] = 1000e18; // 10 USDT minted-against
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("m"), workers, amounts);

        vm.prank(safe);
        escrow.release(JOB);
        vm.prank(safe);
        vault.closeJob(JOB);
        // refund = 850 - 10 = 840 USDT
        assertEq(usdt.balanceOf(founder), 840e6);

        vm.expectRevert(JobVault.JobClosed.selector);
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("m2"), workers, amounts);
    }

    function test_closeJob_requires_release_or_deadline() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        workers[0] = alice;
        amounts[0] = 1000e18;
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("m"), workers, amounts);

        vm.expectRevert(JobVault.HoldbackOpen.selector);
        vm.prank(safe);
        vault.closeJob(JOB);
    }

    function test_createJob_rejects_invalid_holdback() public {
        vm.expectRevert(JobVault.InvalidHoldback.selector);
        vm.prank(safe);
        vault.createJob(JOB, keccak256("catalog-entry"), founder, 850e6, 10_001, acceptor, false);
    }

    function test_cross_batch_funding_covers_desk_liability() public {
        _createJob();
        address[] memory workers = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        workers[0] = alice;
        amounts[0] = 15e13; // 1.5 micro-USDT of GOAT
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("m1"), workers, amounts);
        vm.prank(safe);
        vault.mintBatch(JOB, keccak256("m2"), workers, amounts);
        // Liability floor(3e14 * RATE / 1e18) = 3 micro-USDT; per-batch
        // floors would have funded only 2 — cumulative ceiling funds 3.
        assertEq(usdt.balanceOf(desk), 3);
        assertEq(vault.usdtFunded(JOB), 3);
    }
}
