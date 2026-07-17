// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {EpochSettlement} from "../src/EpochSettlement.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";

/// Invariant fuzz suite for optimistic epoch settlement (spec 2026-07-13):
/// EpochSettlement + HoldbackEscrow + GoatCoin's settlement-mint path.
/// Drives full propose -> warp -> watcher-confirm -> finalize -> claim
/// cycles over a bounded worker pool and cross-checks the Handler's own
/// running totals against on-chain state. No dispute/challenge flow is
/// exercised here — that is covered by EpochSettlement.t.sol's unit tests.
contract Handler is Test {
    EnrollmentRegistry public reg;
    GoatCoin public goat;
    HoldbackEscrow public escrow;
    EpochSettlement public settle;
    WorkerBinding public binding;
    address public safe;
    address public watcher;

    uint256 public constant WORKER_COUNT = 5;
    address[] public workers;

    uint256 public nextEpoch = 1;
    uint256[] public epochs; // every epoch id that reached Finalized this run
    mapping(uint256 => address[]) public epochWorkers;
    mapping(uint256 => uint256[]) public epochScores;

    mapping(address => uint256) public currentScore; // simulated FAH cumulative score (monotonic)
    mapping(address => uint256) public maxSeen; // Handler's mirror of settle.lastClaimedCumulative
    mapping(address => uint256) public paidScore; // sum of capped deltas actually paid per worker

    uint256 public sumLiquid;
    uint256 public sumHoldback;
    uint256 public sumHoldbackOutstanding;
    uint256 public claimsSucceededOnNonFinalized;

    // Disjoint epoch-id namespace for epochs deliberately left in Proposed
    // status (proposed, never confirmed/finalized) so hTryClaimNonFinalized
    // can attempt a VALID-proof claim against a genuinely non-finalized
    // epoch. Starts astronomically far above hProposeConfirmFinalize's
    // sequential `nextEpoch` counter so the two ranges can never collide.
    uint256 public nextProposedEpoch = 1 << 200;
    uint256[] public proposedEpochs; // epoch ids currently stuck in Proposed
    mapping(uint256 => address[]) public proposedEpochWorkers;
    mapping(uint256 => uint256[]) public proposedEpochScores;
    uint256 public badClaimCount; // claimPayout succeeding against a Proposed (non-finalized) epoch

    // Handler is itself the proposer (see hProposeConfirmFinalize), so it
    // must be able to receive its own bond refund from finalizeBatch.
    receive() external payable {}

    constructor(
        EnrollmentRegistry reg_,
        GoatCoin goat_,
        HoldbackEscrow escrow_,
        EpochSettlement settle_,
        address safe_,
        address watcher_
    ) {
        reg = reg_;
        goat = goat_;
        escrow = escrow_;
        settle = settle_;
        binding = settle.binding();
        safe = safe_;
        watcher = watcher_;
        for (uint256 i = 0; i < WORKER_COUNT; i++) {
            address w = makeAddr(string(abi.encodePacked("ev3worker", i)));
            workers.push(w);
            vm.prank(safe);
            reg.setEnrolled(w, true, bytes32(0));
            vm.prank(w);
            binding.bind(string(abi.encodePacked("GOAT-w", vm.toString(i))));
        }
    }

    // ---- merkle helpers -------------------------------------------------
    // Self-consistent tree: pairs are hashed with the same sorted-pair
    // convention as OZ's Hashes.commutativeKeccak256 (which MerkleProof.verify
    // uses), and an odd trailing node is carried up unpaired to the next
    // layer (never duplicated). Root-building and proof-extraction below
    // share this convention, which is all MerkleProof.verify requires.

    function _leaf(address worker, uint256 score) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(worker, score))));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    function _nextLayer(bytes32[] memory layer) internal pure returns (bytes32[] memory next) {
        uint256 n = layer.length;
        uint256 nextLen = (n + 1) / 2;
        next = new bytes32[](nextLen);
        uint256 i = 0;
        for (; i + 1 < n; i += 2) {
            next[i / 2] = _hashPair(layer[i], layer[i + 1]);
        }
        if (n % 2 == 1) {
            next[nextLen - 1] = layer[n - 1];
        }
    }

    function _merkleRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory layer = leaves;
        while (layer.length > 1) {
            layer = _nextLayer(layer);
        }
        return layer[0];
    }

    function _merkleProof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory proof) {
        bytes32[] memory scratch = new bytes32[](16); // >= ceil(log2(WORKER_COUNT)) levels
        uint256 cnt = 0;
        bytes32[] memory layer = leaves;
        uint256 idx = index;
        while (layer.length > 1) {
            uint256 m = layer.length;
            if (idx % 2 == 0) {
                if (idx + 1 < m) scratch[cnt++] = layer[idx + 1];
            } else {
                scratch[cnt++] = layer[idx - 1];
            }
            layer = _nextLayer(layer);
            idx = idx / 2;
        }
        proof = new bytes32[](cnt);
        for (uint256 i = 0; i < cnt; i++) {
            proof[i] = scratch[i];
        }
    }

    // ---- bounded fuzz entry points ---------------------------------------

    /// Drives one full epoch: propose a bonded Merkle-rooted batch over a
    /// bounded subset of workers with monotonically-growing simulated FAH
    /// scores, warp past the challenge window, watcher-confirm, finalize.
    function hProposeConfirmFinalize(uint256 seed) external {
        uint256 n = bound(uint256(keccak256(abi.encode(seed, "n"))), 1, WORKER_COUNT);
        address[] memory ws = new address[](n);
        uint256[] memory scores = new uint256[](n);
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            ws[i] = workers[i];
            uint256 inc = bound(uint256(keccak256(abi.encode(seed, i))), 0, 5_000_000);
            currentScore[ws[i]] += inc;
            scores[i] = currentScore[ws[i]];
            leaves[i] = _leaf(ws[i], scores[i]);
        }
        bytes32 root = _merkleRoot(leaves);

        uint256 epoch = nextEpoch++; // always a fresh (Status.None) epoch id
        uint256 bond = settle.proposerBond();
        vm.deal(address(this), bond);
        settle.proposeBatch{value: bond}(epoch, root, keccak256(abi.encode("evidence", epoch)));

        vm.warp(block.timestamp + settle.challengeWindow() + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch); // permissionless

        epochs.push(epoch);
        epochWorkers[epoch] = ws;
        epochScores[epoch] = scores;
    }

    /// Proposes a bonded Merkle-rooted batch exactly like
    /// hProposeConfirmFinalize but deliberately stops after proposeBatch —
    /// no warp, no watcher confirm, no finalize. The epoch is left sitting
    /// in Status.Proposed forever (its id is drawn from the disjoint
    /// nextProposedEpoch namespace, so no other handler entry point ever
    /// advances it), giving hTryClaimNonFinalized a real non-finalized
    /// epoch with a genuinely valid Merkle proof to probe against.
    function hProposeOnly(uint256 seed) external {
        uint256 n = bound(uint256(keccak256(abi.encode(seed, "pn"))), 1, WORKER_COUNT);
        address[] memory ws = new address[](n);
        uint256[] memory scores = new uint256[](n);
        bytes32[] memory leaves = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            ws[i] = workers[i];
            uint256 inc = bound(uint256(keccak256(abi.encode(seed, "p", i))), 0, 5_000_000);
            currentScore[ws[i]] += inc;
            scores[i] = currentScore[ws[i]];
            leaves[i] = _leaf(ws[i], scores[i]);
        }
        bytes32 root = _merkleRoot(leaves);

        uint256 epoch = nextProposedEpoch++; // fresh Status.None id, disjoint from hProposeConfirmFinalize
        uint256 bond = settle.proposerBond();
        vm.deal(address(this), bond);
        settle.proposeBatch{value: bond}(epoch, root, keccak256(abi.encode("proposed-only-evidence", epoch)));

        proposedEpochs.push(epoch);
        proposedEpochWorkers[epoch] = ws;
        proposedEpochScores[epoch] = scores;
    }

    /// Attempts a claimPayout with a VALID Merkle proof against a
    /// still-Proposed (not-yet-finalized) epoch recorded by hProposeOnly.
    /// This isolates the status guard: unlike hClaim's bogus-epoch/
    /// empty-proof probe (which reverts BadProof regardless of status),
    /// this claim would succeed if the epoch WERE finalized — so a revert
    /// here can only come from the `status == Finalized` check. A regression
    /// that dropped that check would make this claim succeed, incrementing
    /// badClaimCount and failing invariant_only_finalized_paid.
    function hTryClaimNonFinalized(uint256 epochSeed, uint256 workerSeed) external {
        if (proposedEpochs.length == 0) return;
        uint256 epoch = proposedEpochs[epochSeed % proposedEpochs.length];
        address[] memory ws = proposedEpochWorkers[epoch];
        uint256[] memory scores = proposedEpochScores[epoch];
        uint256 idx = workerSeed % ws.length;
        address w = ws[idx];
        uint256 score = scores[idx];

        bytes32[] memory leaves = new bytes32[](ws.length);
        for (uint256 i = 0; i < ws.length; i++) {
            leaves[i] = _leaf(ws[i], scores[i]);
        }
        bytes32[] memory proof = _merkleProof(leaves, idx);

        try settle.claimPayout(epoch, w, score, proof) {
            badClaimCount++;
        } catch {}
    }

    /// Claims for a worker against a finalized epoch's proof, and — every
    /// call — also probes that claiming against a non-finalized (here:
    /// never-proposed) epoch reverts, feeding invariant_only_finalized_paid.
    function hClaim(uint256 workerSeed, uint256 scoreSeed) external {
        address probeWorker = workers[workerSeed % WORKER_COUNT];
        // Astronomically unlikely to collide with a real sequential epoch id.
        uint256 bogusEpoch = uint256(keccak256(abi.encode("bogus-epoch", workerSeed, scoreSeed)));
        bytes32[] memory emptyProof = new bytes32[](0);
        try settle.claimPayout(bogusEpoch, probeWorker, 1, emptyProof) {
            claimsSucceededOnNonFinalized++;
        } catch {}

        if (epochs.length == 0) return;
        uint256 epoch = epochs[scoreSeed % epochs.length];
        address[] memory ws = epochWorkers[epoch];
        uint256[] memory scores = epochScores[epoch];
        uint256 idx = workerSeed % ws.length;
        address w = ws[idx];
        uint256 score = scores[idx];

        bytes32[] memory leaves = new bytes32[](ws.length);
        for (uint256 i = 0; i < ws.length; i++) {
            leaves[i] = _leaf(ws[i], scores[i]);
        }
        bytes32[] memory proof = _merkleProof(leaves, idx);

        uint256 prevWatermark = maxSeen[w];
        uint256 goatBefore = goat.balanceOf(w);
        // Give the time-based rate cap room to mint (capPerDay * elapsed / 1 days).
        vm.warp(block.timestamp + 1 hours);
        bool alreadyClaimed = settle.claimed(epoch, w);
        settle.claimPayout(epoch, w, score, proof);

        uint256 newWatermark = settle.lastClaimedCumulative(w);
        maxSeen[w] = newWatermark;
        if (alreadyClaimed || newWatermark <= prevWatermark) return;

        // Baseline claim (mint 0): watermark jumps, no GOAT. Don't count as paid.
        if (goat.balanceOf(w) == goatBefore) return;

        uint256 capped = newWatermark - prevWatermark;
        paidScore[w] += capped;
        uint256 goatAmount = capped * settle.rate();
        uint256 hb = goatAmount * settle.holdbackBps() / 10_000;
        uint256 liquid = goatAmount - hb;
        sumLiquid += liquid;
        sumHoldback += hb;
        sumHoldbackOutstanding += hb;
    }

    /// Safe-triggered release of a finalized epoch's holdback (mirrors the
    /// worker-property release path so escrow accounting is exercised on
    /// both the credit and release sides, not just credit).
    function hReleaseHoldback(uint256 epochSeed) external {
        if (epochs.length == 0) return;
        uint256 epoch = epochs[epochSeed % epochs.length];
        bytes32 jobId = bytes32(epoch);
        if (escrow.jobReleased(jobId)) return;

        uint256 held;
        for (uint256 i = 0; i < WORKER_COUNT; i++) {
            held += escrow.holdbackOf(jobId, workers[i]);
        }
        if (held == 0) return;

        vm.prank(safe);
        escrow.release(jobId);
        sumHoldbackOutstanding -= held;
    }
}

contract InvariantsV3Test is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    EpochSettlement settle;
    WorkerBinding binding;
    Handler handler;

    address safe = makeAddr("safev3");
    address reserve = makeAddr("reservev3");
    address watcher = makeAddr("watcherv3");

    uint16 constant HB_BPS = 500; // 5% — founder-locked holdback (2026-07-13)
    uint64 constant BACKSTOP = 7 days; // founder-locked backstop
    uint256 constant RATE = uint256(1e18) / 24_000;
    uint256 constant CAP = 2_000_000; // score units; inside the fuzz range so the cap bites (remainder carries forward, FIX 1)
    uint64 constant WINDOW = 12 hours;
    uint256 constant PBOND = 0.01 ether;
    uint256 constant CBOND = 0.01 ether;

    // test_validProofClaim_revertsProposed_succeedsFinalized proposes
    // directly as this test contract, so it must be able to receive its
    // own bond refund from finalizeBatch (mirrors Handler's receive()).
    receive() external payable {}

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        binding = new WorkerBinding();
        // CAP_PER_DAY large so invariant fuzz still exercises payouts under time cap
        settle = new EpochSettlement(
            safe,
            goat,
            escrow,
            reg,
            binding,
            HB_BPS,
            BACKSTOP,
            RATE,
            type(uint256).max / 2,
            WINDOW,
            PBOND,
            CBOND,
            address(0),
            watcher
        );

        vm.startPrank(safe);
        escrow.setVault(address(settle));
        goat.setMinter(address(settle), true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(address(settle), true);
        reg.setSystemAddress(reserve, true);
        vm.stopPrank();

        handler = new Handler(reg, goat, escrow, settle, safe, watcher);
        targetContract(address(handler));
    }

    /// 1. maxSeen[worker] never decreases — enforced by construction in the
    /// Handler (it only ever advances on a real proven score), and here
    /// cross-checked against the contract's own high-water mark so a
    /// contract-side regression (e.g. an unguarded watermark write) would
    /// show up as a mismatch, not just an internal Handler inconsistency.
    function invariant_watermark_monotonic() public view {
        for (uint256 i = 0; i < handler.WORKER_COUNT(); i++) {
            address w = handler.workers(i);
            assertEq(settle.lastClaimedCumulative(w), handler.maxSeen(w));
        }
    }

    /// 2. Every GOAT in existence came from a claimPayout mint — no other
    /// mint path exists (settle is the sole registered minter).
    function invariant_no_mint_beyond_claims() public view {
        assertEq(goat.totalSupply(), handler.sumLiquid() + handler.sumHoldback());
    }

    /// 3. claimPayout on a non-Finalized batch must always revert
    /// (WrongStatus). Primary guard: hTryClaimNonFinalized attempts a
    /// claim with a VALID Merkle proof (verifiable by construction — see
    /// hProposeOnly) against an epoch left in Status.Proposed, so success
    /// can only be explained by a missing/broken status guard. The older
    /// bogus-epoch/empty-proof probe (hClaim, every call) is kept as a
    /// secondary check but is over-determined on its own: an empty proof
    /// reverts BadProof regardless of status, so it would not catch a
    /// regression that dropped the status check.
    function invariant_only_finalized_paid() public view {
        assertEq(handler.claimsSucceededOnNonFinalized(), 0);
        assertEq(handler.badClaimCount(), 0);
    }

    /// 4. Holdback GOAT actually held in escrow can never fall below what's
    /// been credited-but-not-yet-released.
    function invariant_escrow_solvency() public view {
        assertGe(goat.balanceOf(address(escrow)), handler.sumHoldbackOutstanding());
    }

    /// 5. No worker's total paid-for score ever exceeds their max proven
    /// cumulative — the per-worker watermark prevents paying for the same
    /// score twice (paidScore can be strictly less when the epoch cap bites).
    function invariant_no_double_pay() public view {
        for (uint256 i = 0; i < handler.WORKER_COUNT(); i++) {
            address w = handler.workers(i);
            assertLe(handler.paidScore(w), settle.lastClaimedCumulative(w));
        }
    }

    /// Deterministic sanity check for the hTryClaimNonFinalized probe added
    /// to strengthen invariant_only_finalized_paid: the exact same
    /// (worker, score, proof) reverts WrongStatus while the epoch sits in
    /// Status.Proposed, then succeeds once that same epoch is confirmed and
    /// finalized. This proves the probe's proof is genuinely valid — the
    /// revert it observes during the fuzz run is caused by the status
    /// guard, not by a malformed/empty proof (which is exactly the gap in
    /// the old bogus-epoch probe).
    function test_validProofClaim_revertsProposed_succeedsFinalized() public {
        address worker = makeAddr("sanityWorker");
        uint256 score = 42;

        vm.prank(safe);
        reg.setEnrolled(worker, true, bytes32(0));
        vm.prank(worker);
        binding.bind("GOAT-sanity");
        assertTrue(binding.bound(worker));

        // Single-leaf tree: root == leaf, proof is empty. Same leaf/root
        // convention as Handler._leaf / claimPayout's own leaf hash.
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(worker, score))));
        bytes32[] memory emptyProof = new bytes32[](0);

        uint256 epoch = 999_999;
        uint256 bond = settle.proposerBond();
        vm.deal(address(this), bond);
        settle.proposeBatch{value: bond}(epoch, leaf, keccak256("sanity-evidence"));

        // Still Proposed: valid-proof claim must revert WrongStatus.
        vm.expectRevert(EpochSettlement.WrongStatus.selector);
        settle.claimPayout(epoch, worker, score, emptyProof);

        // Confirm + finalize, then claim succeeds (baseline mint 0).
        vm.warp(block.timestamp + settle.challengeWindow() + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch);

        settle.claimPayout(epoch, worker, score, emptyProof);
        assertTrue(settle.hasBaseline(worker));
        assertEq(settle.lastClaimedCumulative(worker), score);
        assertEq(goat.balanceOf(worker), 0, "baseline mints 0");

        // Second finalized batch at higher score mints after time-cap room.
        uint256 score2 = score + 24_000;
        bytes32 leaf2 = keccak256(bytes.concat(keccak256(abi.encode(worker, score2))));
        uint256 epoch2 = 1_000_000;
        vm.deal(address(this), bond);
        settle.proposeBatch{value: bond}(epoch2, leaf2, keccak256("sanity-2"));
        vm.warp(block.timestamp + settle.challengeWindow() + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch2);
        settle.finalizeBatch(epoch2);
        vm.warp(uint256(settle.lastClaimTime(worker)) + 1 days);
        settle.claimPayout(epoch2, worker, score2, emptyProof);
        assertGt(goat.balanceOf(worker), 0);
    }
}
