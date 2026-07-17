// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {EpochSettlement} from "../src/EpochSettlement.sol";
import {FounderResolver} from "../src/FounderResolver.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";

contract EpochSettlementKeeperFeeTest is Test {
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
    address bob = makeAddr("bob");
    address proposer = makeAddr("proposer");
    address challenger = makeAddr("challenger");

    uint16 constant HB_BPS = 500; // 5%
    uint64 constant BACKSTOP = 7 days; // 604800
    uint256 constant RATE = uint256(1e18) / 24000; // ~1 GOAT per 24000 score
    uint256 constant CAP_PER_DAY = 10_000e18; // high so legacy tests not rate-capped
    uint64 constant WINDOW = 12 hours; // 43200
    uint256 constant PBOND = 0.01 ether;
    uint256 constant CBOND = 0.01 ether;

    event ParamSet(bytes32 indexed key, uint256 value);
    event KeeperFeePaid(uint256 indexed epoch, address indexed worker, address indexed keeper, uint256 fee);

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
        reg.setEnrolled(alice, true, bytes32(0));
        reg.setEnrolled(bob, true, bytes32(0));
        settle.setResolver(address(resolver));
        vm.stopPrank();
        vm.prank(alice);
        binding.bind("GOAT-alice");
        vm.prank(bob);
        binding.bind("GOAT-bob");
        vm.deal(proposer, 1 ether);
        vm.deal(challenger, 1 ether);
    }

    function _leaf(address w, uint256 s) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(w, s))));
    }

    function _root2(bytes32 l0, bytes32 l1) internal pure returns (bytes32) {
        return l0 < l1 ? keccak256(abi.encode(l0, l1)) : keccak256(abi.encode(l1, l0));
    }

    function _propose(uint256 epoch) internal {
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(epoch, keccak256("root-1"), keccak256("evidence"));
    }

    function _finalizeClean(uint256 epoch) internal {
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch);
    }

    /// Propose+finalize a single-leaf (alice-only) epoch at `score`, then claim
    /// with an empty proof (root == leaf).
    function _proposeFinalizeSingle(uint256 epoch, uint256 score) internal {
        bytes32 leaf = _leaf(alice, score);
        vm.prank(proposer);
        vm.deal(proposer, 1 ether);
        settle.proposeBatch{value: PBOND}(epoch, leaf, bytes32(0));
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch);
    }

    function test_claim_keeperFee_baselineThenDailyWithFee() public {
        bytes32[] memory empty = new bytes32[](0);

        // Baseline claim mint 0
        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);
        assertTrue(settle.hasBaseline(alice));
        assertEq(goat.balanceOf(alice), 0);

        vm.prank(safe);
        settle.setKeeperFee(1e18);

        address keeper = makeAddr("keeper");
        uint256 aScore = 2_400_000;
        _proposeFinalizeSingle(2, aScore);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);

        vm.prank(keeper);
        settle.claimPayout(2, alice, aScore, empty);

        uint256 gross = aScore * RATE;
        uint256 hb = gross * HB_BPS / 10_000;
        uint256 fee = 1e18;
        uint256 liquid = gross - hb - fee;

        assertEq(goat.balanceOf(alice), liquid);
        assertEq(goat.balanceOf(keeper), fee);
        assertEq(settle.lastClaimedCumulative(alice), aScore);
        assertEq(escrow.holdbackOf(bytes32(uint256(2)), alice), hb);
    }

    function test_claim_keeperFee_liquidLessThanFee() public {
        bytes32[] memory empty = new bytes32[](0);

        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);

        vm.prank(safe);
        settle.setKeeperFee(type(uint256).max);

        address keeper = makeAddr("keeper");
        uint256 aScore = 2_400_000;
        _proposeFinalizeSingle(2, aScore);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);

        vm.prank(keeper);
        settle.claimPayout(2, alice, aScore, empty);

        uint256 gross = aScore * RATE;
        uint256 hb = gross * HB_BPS / 10_000;
        uint256 liquid = gross - hb;

        // Fee takes entire liquid; worker gets 0 liquid; holdback still full from gross
        assertEq(goat.balanceOf(alice), 0);
        assertEq(goat.balanceOf(keeper), liquid);
        assertEq(escrow.holdbackOf(bytes32(uint256(2)), alice), hb);
        assertEq(settle.lastClaimedCumulative(alice), aScore);
    }

    function test_claim_keeperFee_selfClaim() public {
        bytes32[] memory empty = new bytes32[](0);

        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);

        vm.prank(safe);
        settle.setKeeperFee(1e18);

        uint256 aScore = 2_400_000;
        _proposeFinalizeSingle(2, aScore);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);

        vm.prank(alice);
        settle.claimPayout(2, alice, aScore, empty);

        uint256 gross = aScore * RATE;
        uint256 hb = gross * HB_BPS / 10_000;
        // Alice nets gross - holdback (fee minted to herself)
        assertEq(goat.balanceOf(alice), gross - hb);
        assertEq(escrow.holdbackOf(bytes32(uint256(2)), alice), hb);
        assertEq(settle.lastClaimedCumulative(alice), aScore);
    }

    function test_claim_keeperFee_zeroFeeUnchanged() public {
        bytes32[] memory empty = new bytes32[](0);

        // keeperFee default 0
        assertEq(settle.keeperFee(), 0);

        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);

        address thirdParty = makeAddr("thirdParty");
        uint256 aScore = 2_400_000;
        _proposeFinalizeSingle(2, aScore);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);

        vm.prank(thirdParty);
        settle.claimPayout(2, alice, aScore, empty);

        uint256 gross = aScore * RATE;
        uint256 hb = gross * HB_BPS / 10_000;
        uint256 liquid = gross - hb;

        assertEq(goat.balanceOf(alice), liquid);
        assertEq(escrow.holdbackOf(bytes32(uint256(2)), alice), hb);
        assertEq(settle.lastClaimedCumulative(alice), aScore);
        assertEq(goat.balanceOf(thirdParty), 0);
    }

    function test_claim_keeperFee_cappedScoreZero_noFee() public {
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(safe);
        settle.setKeeperFee(1e18);

        address keeper = makeAddr("keeper");
        uint256 aScore = 2_400_000;

        // Finalize both epochs first so warps complete BEFORE baseline stamps lastClaimTime.
        _proposeFinalizeSingle(1, 0);
        _proposeFinalizeSingle(2, aScore);

        // Baseline now — lastClaimTime = block.timestamp
        settle.claimPayout(1, alice, 0, empty);
        assertTrue(settle.hasBaseline(alice));

        // Same timestamp, no warp → elapsed == 0 → maxGoat == 0 → cappedScore == 0 early return
        vm.prank(keeper);
        settle.claimPayout(2, alice, aScore, empty);

        assertEq(goat.balanceOf(alice), 0);
        assertEq(goat.balanceOf(keeper), 0);
        assertFalse(settle.claimed(2, alice));
        assertEq(settle.lastClaimedCumulative(alice), 0); // baseline was score 0
    }

    function test_setKeeperFee_onlySafeAndEmits() public {
        vm.expectRevert(EpochSettlement.NotSafe.selector);
        settle.setKeeperFee(1e18);

        uint256 v = 5e17;
        vm.prank(safe);
        vm.expectEmit(true, true, true, true);
        emit ParamSet("keeperFee", v);
        settle.setKeeperFee(v);
        assertEq(settle.keeperFee(), v);
    }
}
