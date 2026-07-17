// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {EpochSettlement} from "../src/EpochSettlement.sol";
import {FounderResolver} from "../src/FounderResolver.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";

/// Attribution path: baseline mint-0, time-based cap, binding require.
contract EpochSettlementAttributionTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    EpochSettlement settle;
    FounderResolver resolver;
    WorkerBinding binding;

    address safe = makeAddr("safe");
    address reserve = makeAddr("reserve");
    address founder = makeAddr("founder");
    address watcher = makeAddr("watcher");
    address alice = makeAddr("alice");
    address proposer = makeAddr("proposer");

    uint16 constant HB_BPS = 500;
    uint64 constant BACKSTOP = 7 days;
    uint256 constant RATE = uint256(1e18) / 24000;
    uint256 constant CAP_PER_DAY = 67e18; // 67 GOAT/day
    uint64 constant WINDOW = 12 hours;
    uint256 constant PBOND = 0.01 ether;
    uint256 constant CBOND = 0.01 ether;

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        binding = new WorkerBinding();
        settle = new EpochSettlement(
            safe,
            goat,
            escrow,
            reg,
            binding,
            HB_BPS,
            BACKSTOP,
            RATE,
            CAP_PER_DAY,
            WINDOW,
            PBOND,
            CBOND,
            address(0),
            watcher
        );
        resolver = new FounderResolver(founder, address(settle));
        vm.startPrank(safe);
        escrow.setVault(address(settle));
        goat.setMinter(address(settle), true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(address(settle), true);
        reg.setSystemAddress(reserve, true);
        settle.setResolver(address(resolver));
        vm.stopPrank();
        vm.deal(proposer, 1 ether);

        // permissionless enroll + bind
        vm.prank(alice);
        reg.enrollSelf();
        vm.prank(alice);
        binding.bind("GOAT-alice");
    }

    function _finalizeEmptyProofEpoch(uint256 epoch, bytes32 root) internal {
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(epoch, root, keccak256("ev"));
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch);
    }

    /// Single-leaf merkle: leaf = double-hash(abi.encode(worker, score)).
    function _leaf(address worker, uint256 score) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(worker, score))));
    }

    function test_baseline_firstClaimMintsZero() public {
        uint256 B = 100_000;
        bytes32 root = _leaf(alice, B);
        _finalizeEmptyProofEpoch(1, root);

        bytes32[] memory empty;
        uint256 balBefore = goat.balanceOf(alice);
        settle.claimPayout(1, alice, B, empty);
        assertEq(goat.balanceOf(alice), balBefore, "baseline mints 0");
        assertTrue(settle.hasBaseline(alice));
        assertEq(settle.lastClaimedCumulative(alice), B);
        assertEq(settle.lastClaimTime(alice), uint64(block.timestamp));
    }

    function test_secondClaimMintsDeltaTimesRate() public {
        uint256 B = 100_000;
        uint256 P = 124_000; // +24_000 score ≈ 1 GOAT at RATE
        bytes32 root1 = _leaf(alice, B);
        _finalizeEmptyProofEpoch(1, root1);
        bytes32[] memory empty;
        settle.claimPayout(1, alice, B, empty); // baseline

        bytes32 root2 = _leaf(alice, P);
        _finalizeEmptyProofEpoch(2, root2);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days); // full day of cap room
        uint256 balBefore = goat.balanceOf(alice);
        settle.claimPayout(2, alice, P, empty);
        uint256 expected = (P - B) * RATE; // no cap hit for 1 GOAT << 67
        // 95% liquid (5% holdback)
        uint256 liquid = expected - (expected * HB_BPS / 10_000);
        assertEq(goat.balanceOf(alice) - balBefore, liquid);
        assertEq(settle.lastClaimedCumulative(alice), P);
    }

    function test_unboundReverts() public {
        address carol = makeAddr("carol");
        vm.prank(carol);
        reg.enrollSelf();
        // no bind
        uint256 S = 50;
        bytes32 root = _leaf(carol, S);
        _finalizeEmptyProofEpoch(1, root);
        bytes32[] memory empty;
        vm.expectRevert(EpochSettlement.NotBound.selector);
        settle.claimPayout(1, carol, S, empty);
    }

    function test_timeBasedCap_limitsDailyMint() public {
        // baseline 0, then huge proven score — only ~67 GOAT after 1 day
        bytes32 root1 = _leaf(alice, 0);
        _finalizeEmptyProofEpoch(1, root1);
        bytes32[] memory empty;
        settle.claimPayout(1, alice, 0, empty);

        uint256 huge = 1e12; // enormous score delta
        bytes32 root2 = _leaf(alice, huge);
        _finalizeEmptyProofEpoch(2, root2);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);
        settle.claimPayout(2, alice, huge, empty);
        // liquid + holdback == goat minted ≤ capPerDay (+1 score-unit floor rounding)
        uint256 totalMinted = goat.totalSupply();
        assertLe(totalMinted, CAP_PER_DAY + RATE);
        // watermark advanced by floor(minted/rate), not full huge
        assertLt(settle.lastClaimedCumulative(alice), huge);
        assertGt(settle.lastClaimedCumulative(alice), 0);
    }

    function test_selfEnroll_blacklistedBlocks() public {
        address eve = makeAddr("eve");
        vm.prank(safe);
        reg.setBlacklisted(eve, true);
        vm.prank(eve);
        vm.expectRevert(EnrollmentRegistry.Blacklisted.selector);
        reg.enrollSelf();
    }
}
