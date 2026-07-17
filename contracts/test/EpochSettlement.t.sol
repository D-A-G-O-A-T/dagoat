// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {EpochSettlement} from "../src/EpochSettlement.sol";
import {FounderResolver} from "../src/FounderResolver.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";

contract EpochSettlementTest is Test {
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

    function test_immutablesAndParams() public view {
        assertEq(settle.safe(), safe);
        assertEq(address(settle.goat()), address(goat));
        assertEq(address(settle.escrow()), address(escrow));
        assertEq(settle.holdbackBps(), HB_BPS);
        assertEq(settle.holdbackBackstop(), BACKSTOP);
        assertEq(settle.rate(), RATE);
        assertEq(settle.challengeWindow(), WINDOW);
        assertEq(settle.watcher(), watcher);
        assertEq(settle.resolver(), address(resolver));
    }

    function test_setters_onlySafe() public {
        vm.expectRevert(EpochSettlement.NotSafe.selector);
        settle.setRate(1);
        vm.prank(safe);
        settle.setRate(999);
        assertEq(settle.rate(), 999);
    }

    bytes32 constant ROOT = keccak256("root-1");

    function _propose(uint256 epoch) internal {
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(epoch, ROOT, keccak256("evidence"));
    }

    function test_propose_setsBatchAndPullsBond() public {
        uint256 balBefore = address(settle).balance;
        _propose(1);
        (address p, uint256 pb,,, bytes32 root, uint256 r,, uint64 dl,, EpochSettlement.Status st) = settle.batches(1);
        assertEq(p, proposer);
        assertEq(pb, PBOND);
        assertEq(root, ROOT);
        assertEq(r, RATE);
        assertEq(dl, uint64(block.timestamp) + WINDOW);
        assertEq(uint256(st), uint256(EpochSettlement.Status.Proposed));
        assertEq(address(settle).balance, balBefore + PBOND);
    }

    function test_propose_wrongBondReverts() public {
        vm.prank(proposer);
        vm.expectRevert(EpochSettlement.BondMismatch.selector);
        settle.proposeBatch{value: PBOND - 1}(1, ROOT, bytes32(0));
    }

    function test_propose_twiceReverts() public {
        _propose(1);
        vm.prank(proposer);
        vm.expectRevert(EpochSettlement.WrongStatus.selector);
        settle.proposeBatch{value: PBOND}(1, ROOT, bytes32(0));
    }

    function test_challenge_withinWindow() public {
        _propose(1);
        vm.prank(challenger);
        settle.challengeBatch{value: CBOND}(1, keccak256("counter"));
        (,, address c, uint256 cb,,,,,, EpochSettlement.Status st) = settle.batches(1);
        assertEq(c, challenger);
        assertEq(cb, CBOND);
        assertEq(uint256(st), uint256(EpochSettlement.Status.Challenged));
    }

    function test_challenge_afterWindowReverts() public {
        _propose(1);
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(challenger);
        vm.expectRevert(EpochSettlement.WindowClosed.selector);
        settle.challengeBatch{value: CBOND}(1, bytes32(0));
    }

    function test_settleDispute_onlyResolver() public {
        _propose(1);
        vm.prank(challenger);
        settle.challengeBatch{value: CBOND}(1, bytes32(0));
        vm.expectRevert(EpochSettlement.NotResolver.selector);
        settle.settleDispute(1, true, bytes32(0));
    }

    function test_settleDispute_proposerWon_paysProposer() public {
        _propose(1);
        vm.prank(challenger);
        settle.challengeBatch{value: CBOND}(1, bytes32(0));
        uint256 pBefore = proposer.balance;
        vm.prank(founder);
        resolver.decide(1, true, keccak256("ok"));
        (,,,,,,,,, EpochSettlement.Status st) = settle.batches(1);
        assertEq(uint256(st), uint256(EpochSettlement.Status.ProposerWon));
        assertEq(proposer.balance, pBefore + CBOND); // won the challenger's bond
    }

    function test_settleDispute_challengerWon_reopens() public {
        _propose(1);
        vm.prank(challenger);
        settle.challengeBatch{value: CBOND}(1, bytes32(0));
        uint256 cBefore = challenger.balance;
        vm.prank(founder);
        resolver.decide(1, false, keccak256("fraud"));
        (,,,,,,,,, EpochSettlement.Status st) = settle.batches(1);
        assertEq(uint256(st), uint256(EpochSettlement.Status.ChallengerWon));
        assertEq(challenger.balance, cBefore + PBOND + CBOND); // own bond back + proposer's forfeited bond
        // reopenable:
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(1, keccak256("root-2"), bytes32(0));
        (,,,,,,,,, EpochSettlement.Status st2) = settle.batches(1);
        assertEq(uint256(st2), uint256(EpochSettlement.Status.Proposed));
    }

    function _finalizeClean(uint256 epoch) internal {
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch);
    }

    function test_confirm_onlyWatcher() public {
        _propose(1);
        vm.warp(block.timestamp + WINDOW + 1);
        vm.expectRevert(EpochSettlement.NotWatcher.selector);
        settle.confirmEpoch(1);
    }

    function test_confirm_beforeWindowCloseReverts() public {
        _propose(1);
        vm.prank(watcher);
        vm.expectRevert(EpochSettlement.WindowOpen.selector);
        settle.confirmEpoch(1);
    }

    function test_finalize_requiresConfirmation() public {
        _propose(1);
        vm.warp(block.timestamp + WINDOW + 1);
        vm.expectRevert(EpochSettlement.NotConfirmed.selector);
        settle.finalizeBatch(1); // no watcher confirmation → cannot finalize (heartbeat gate)
    }

    function test_finalize_cleanPath_returnsBondAndFinalizes() public {
        _propose(1);
        uint256 pBefore = proposer.balance;
        _finalizeClean(1);
        (,,,,,,,,, EpochSettlement.Status st) = settle.batches(1);
        assertEq(uint256(st), uint256(EpochSettlement.Status.Finalized));
        assertEq(proposer.balance, pBefore + PBOND); // honest proposer bond returned
    }

    function test_finalize_beforeWindowReverts() public {
        _propose(1);
        vm.prank(watcher);
        vm.expectRevert(EpochSettlement.WindowOpen.selector);
        settle.confirmEpoch(1); // window still open — cannot even confirm
    }

    // Build a 2-leaf OZ-standard tree for (alice, aScore) and (bob, bScore).
    function _leaf(address w, uint256 s) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(w, s))));
    }

    function _root2(bytes32 l0, bytes32 l1) internal pure returns (bytes32) {
        return l0 < l1 ? keccak256(abi.encode(l0, l1)) : keccak256(abi.encode(l1, l0));
    }

    function test_claim_paysSplitAndAdvancesWatermark() public {
        uint256 aScore = 2_400_000;
        uint256 bScore = 600_000;
        bytes32[] memory empty = new bytes32[](0);

        // Enrollment baseline (mint 0)
        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);
        assertTrue(settle.hasBaseline(alice));
        assertEq(goat.balanceOf(alice), 0);

        bytes32 la = _leaf(alice, aScore);
        bytes32 lb = _leaf(bob, bScore);
        bytes32 root = _root2(la, lb);
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(2, root, bytes32(0));
        _finalizeClean(2);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);

        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = lb;
        settle.claimPayout(2, alice, aScore, proofA);

        uint256 expectGross = aScore * RATE;
        uint256 expectHb = expectGross * HB_BPS / 10_000;
        uint256 expectLiquid = expectGross - expectHb;
        assertEq(goat.balanceOf(alice), expectLiquid);
        assertEq(escrow.holdbackOf(bytes32(uint256(2)), alice), expectHb);
        assertEq(settle.lastClaimedCumulative(alice), aScore);
    }

    function test_claim_idempotentNoDoublePay() public {
        bytes32[] memory empty = new bytes32[](0);
        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);

        uint256 aScore = 1_000_000;
        bytes32 la = _leaf(alice, aScore);
        bytes32 lb = _leaf(bob, 1);
        bytes32 root = _root2(la, lb);
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(2, root, bytes32(0));
        _finalizeClean(2);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);
        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = lb;
        settle.claimPayout(2, alice, aScore, proofA);
        uint256 balAfterFirst = goat.balanceOf(alice);
        settle.claimPayout(2, alice, aScore, proofA); // same epoch: no-op
        assertEq(goat.balanceOf(alice), balAfterFirst);
    }

    function test_claim_unenrolledSkipped() public {
        address carol = makeAddr("carol"); // not enrolled
        uint256 cScore = 500_000;
        bytes32 lc = _leaf(carol, cScore);
        bytes32 lb = _leaf(bob, 1);
        bytes32 root = _root2(lc, lb);
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(1, root, bytes32(0));
        _finalizeClean(1);
        bytes32[] memory proofC = new bytes32[](1);
        proofC[0] = lb;
        settle.claimPayout(1, carol, cScore, proofC); // skipped, no revert
        assertEq(goat.balanceOf(carol), 0);
        assertEq(settle.lastClaimedCumulative(carol), 0);
    }

    function test_claim_timeCapApplied() public {
        // 1 day of room → max mint CAP_SCORE * RATE GOAT where CAP_SCORE = 100_000
        uint256 scoreCap = 100_000;
        vm.prank(safe);
        settle.setCapPerDay(scoreCap * RATE);
        bytes32[] memory empty = new bytes32[](0);
        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);

        uint256 aScore = 5_000_000; // way over one day of score-cap
        _proposeFinalizeSingle(2, aScore);
        // Cap is time-based from lastClaimTime (baseline), not from "now + 1 day" after extra warps.
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);
        settle.claimPayout(2, alice, aScore, empty);
        uint256 cappedGross = scoreCap * RATE;
        uint256 cappedLiquid = cappedGross - cappedGross * HB_BPS / 10_000;
        assertEq(goat.balanceOf(alice), cappedLiquid);
        assertEq(settle.lastClaimedCumulative(alice), scoreCap);
    }

    function test_claim_beforeFinalizedReverts() public {
        _propose(1);
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(EpochSettlement.WrongStatus.selector);
        settle.claimPayout(1, alice, 1, empty);
    }

    // ---- FIX 1: non-forfeiting per-epoch cap (over-cap remainder carries forward) ----

    event Claimed(
        uint256 indexed epoch, address indexed worker, uint256 liquid, uint256 holdback, uint256 newCumulative
    );

    /// Propose+finalize a single-leaf (alice-only) epoch at `score`, then claim
    /// with an empty proof (root == leaf). Returns liquid minted for the delta.
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

    function test_claim_capCarriesOverAcrossEpochs() public {
        // Time-based cap: each full day allows `cap` score-units of mint (as GOAT = cap * RATE).
        uint256 cap = 100_000;
        vm.prank(safe);
        settle.setCapPerDay(cap * RATE);

        uint256 finalProven = 250_000;
        bytes32[] memory empty = new bytes32[](0);

        // Baseline
        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);

        // Day 1 earn
        _proposeFinalizeSingle(2, finalProven);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);
        settle.claimPayout(2, alice, finalProven, empty);
        assertEq(settle.lastClaimedCumulative(alice), cap);

        // Day 2
        _proposeFinalizeSingle(3, finalProven);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);
        settle.claimPayout(3, alice, finalProven, empty);
        assertEq(settle.lastClaimedCumulative(alice), 2 * cap);

        // Day 3 drains remainder (50k)
        _proposeFinalizeSingle(4, finalProven);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);
        settle.claimPayout(4, alice, finalProven, empty);
        assertEq(settle.lastClaimedCumulative(alice), finalProven);

        uint256 totalMinted = goat.balanceOf(alice) + escrow.holdbackOf(bytes32(uint256(2)), alice)
            + escrow.holdbackOf(bytes32(uint256(3)), alice) + escrow.holdbackOf(bytes32(uint256(4)), alice);
        assertEq(totalMinted, finalProven * RATE, "no forfeiture across days");
    }

    /// Same-epoch loop cannot bypass the claimed guard (still true with time-based cap).
    function test_claim_capNotBypassableBySameEpochLoop() public {
        uint256 cap = 100_000;
        vm.prank(safe);
        settle.setCapPerDay(cap * RATE);
        uint256 finalProven = 250_000;
        bytes32[] memory empty = new bytes32[](0);

        _proposeFinalizeSingle(1, 0);
        settle.claimPayout(1, alice, 0, empty);
        _proposeFinalizeSingle(2, finalProven);
        vm.warp(uint256(settle.lastClaimTime(alice)) + 1 days);
        settle.claimPayout(2, alice, finalProven, empty);
        uint256 afterFirst = goat.balanceOf(alice) + escrow.holdbackOf(bytes32(uint256(2)), alice);
        assertEq(afterFirst, cap * RATE, "first earn claim mints exactly one day of cap");
        assertEq(settle.lastClaimedCumulative(alice), cap);
        assertTrue(settle.claimed(2, alice));

        // Loop the SAME finalized epoch — must mint nothing more.
        settle.claimPayout(2, alice, finalProven, empty);
        settle.claimPayout(2, alice, finalProven, empty);
        uint256 afterLoop = goat.balanceOf(alice) + escrow.holdbackOf(bytes32(uint256(2)), alice);
        assertEq(afterLoop, afterFirst, "same-epoch re-claims mint nothing more");
        assertEq(settle.lastClaimedCumulative(alice), cap, "watermark unchanged by the same-epoch loop");
    }

    // ---- FIX 2: permissionless finalize after watcher-offline grace timeout ----

    function test_setWatcherGrace_onlySafe() public {
        vm.expectRevert(EpochSettlement.NotSafe.selector);
        settle.setWatcherGrace(3 days);
        vm.prank(safe);
        settle.setWatcherGrace(3 days);
        assertEq(settle.watcherGrace(), 3 days);
    }

    function test_watcherGrace_defaultIsOneDay() public view {
        assertEq(settle.watcherGrace(), 1 days);
    }

    function test_finalize_timeout_beforeDeadlineReverts() public {
        _propose(1);
        // Window still open: WindowOpen regardless of grace.
        vm.expectRevert(EpochSettlement.WindowOpen.selector);
        settle.finalizeBatch(1);
    }

    function test_finalize_timeout_afterDeadlineBeforeGraceReverts() public {
        _propose(1);
        // Past challenge deadline but within grace, no watcher confirm -> NotConfirmed.
        vm.warp(block.timestamp + WINDOW + 1);
        vm.expectRevert(EpochSettlement.NotConfirmed.selector);
        settle.finalizeBatch(1);
    }

    function test_finalize_timeout_permissionlessAfterGrace() public {
        _propose(1);
        uint256 pBefore = proposer.balance;
        // Past deadline + watcherGrace, still no watcher confirm -> ANY address can finalize.
        vm.warp(block.timestamp + WINDOW + uint256(settle.watcherGrace()) + 1);
        address rando = makeAddr("randoFinalizer");
        vm.prank(rando);
        settle.finalizeBatch(1);
        (,,,,,,,,, EpochSettlement.Status st) = settle.batches(1);
        assertEq(uint256(st), uint256(EpochSettlement.Status.Finalized));
        assertEq(proposer.balance, pBefore + PBOND, "honest proposer bond still returned on timeout finalize");
    }

    function test_finalize_watcherFastPathStillImmediate() public {
        _propose(1);
        uint256 pBefore = proposer.balance;
        // Right after the deadline (well before grace elapses), a watcher confirm
        // still finalizes immediately — the fast path is unchanged.
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(watcher);
        settle.confirmEpoch(1);
        address rando = makeAddr("randoFinalizer2");
        vm.prank(rando);
        settle.finalizeBatch(1);
        (,,,,,,,,, EpochSettlement.Status st) = settle.batches(1);
        assertEq(uint256(st), uint256(EpochSettlement.Status.Finalized));
        assertEq(proposer.balance, pBefore + PBOND);
    }
}
