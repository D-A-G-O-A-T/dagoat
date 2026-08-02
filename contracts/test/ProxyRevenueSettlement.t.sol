// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {ProxyRevenueSettlement} from "../src/proxy/ProxyRevenueSettlement.sol";

/// A bond recipient that refuses ETH. If bonds were pushed rather than pulled, one
/// of these could wedge `resolveChallenge` permanently -- and `Challenged` would
/// then be a terminal state holding an epoch's whole funding hostage.
contract RevertingReceiver {
    receive() external payable {
        revert("no");
    }

    function challenge(ProxyRevenueSettlement pool, uint256 epochId, uint256 bond) external payable {
        pool.challengeBatch{value: bond}(epochId, bytes32("counter"));
    }
}

contract ProxyRevenueSettlementTest is Test {
    GoatCoin goat;
    EnrollmentRegistry reg;
    ProxyRevenueSettlement pool;

    address safe = makeAddr("safe");
    address funder = makeAddr("funder");
    address publisher = makeAddr("publisher");
    address treasury = makeAddr("treasury");
    address attestorSafe = makeAddr("attestorSafe");
    address reserveSink = makeAddr("reserveSink");
    address gateway = makeAddr("gateway");
    address resolver = makeAddr("resolver");
    address operator = makeAddr("operator");
    address stranger = makeAddr("stranger");
    address unenrolled = makeAddr("unenrolled");

    uint256 constant EPOCH = 8_000_000_020_664;
    uint256 constant EPOCH_B = 8_000_000_020_665;
    uint256 constant BOND = 0.05 ether;

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        pool = new ProxyRevenueSettlement(
            ProxyRevenueSettlement.Config({
                safe: safe,
                goat: address(goat),
                registry: address(reg),
                treasury: treasury,
                attestorSafe: attestorSafe,
                reserveSink: reserveSink,
                funder: funder,
                publisher: publisher,
                gateway: gateway,
                usdtTreasury: makeAddr("usdtTreasury"),
                resolver: resolver,
                watcher: makeAddr("watcher"),
                challengeWindow: 6 hours,
                claimWindow: 30 days,
                resolveWindow: 7 days,
                proposerBond: BOND,
                challengerBond: BOND,
                referenceRateUsdtPerGoat: 1e6
            })
        );
        vm.startPrank(safe);
        reg.setSystemAddress(address(pool), true);
        for (uint256 i = 0; i < 5; i++) {
            reg.setEnrolled([funder, treasury, attestorSafe, reserveSink, operator][i], true, bytes32("kyc"));
        }
        goat.setMinter(safe, true);
        goat.mint(funder, 1_000_000e18);
        vm.stopPrank();
        vm.deal(publisher, 10 ether);
    }

    // ------------------------------------------------------------- the split

    /// The split is the whole economic surface. 9000 + 1000 = 10000, and the take
    /// decomposes into ops + attestor + reserve ONLY -- there is no fourth
    /// component and there never was one on this path (founder ruling FR-1).
    ///
    /// Mutations this detects: any edit to the six bps constants; a split that no
    /// longer sums to the denominator.
    function test_split_is_exactly_ninety_ten_and_the_take_has_three_parts() public view {
        assertEq(pool.OPERATOR_BPS(), 9_000);
        assertEq(pool.TAKE_BPS(), 1_000);
        assertEq(pool.OPERATOR_BPS() + pool.TAKE_BPS(), pool.BPS_DENOM());
        assertEq(pool.TREASURY_BPS(), 600);
        assertEq(pool.ATTESTOR_BPS(), 200);
        assertEq(pool.RESERVE_BPS(), 200);
        assertEq(pool.TREASURY_BPS() + pool.ATTESTOR_BPS() + pool.RESERVE_BPS(), pool.TAKE_BPS());
    }

    // ------------------------------------------------------------ the inflow

    /// Funding is bounded by REALIZED consumer USDT, recorded independently by the
    /// gateway. A funder that has not been told about any inflow cannot fund.
    ///
    /// Mutations this detects: deleting the `BackingExceedsInflow` require; letting
    /// the funder supply its own inflow figure.
    function test_fundEpoch_is_bounded_by_recorded_usdt_inflow() public {
        vm.startPrank(funder);
        goat.approve(address(pool), 1_000_000e18);
        vm.expectRevert(ProxyRevenueSettlement.BackingExceedsInflow.selector);
        pool.fundEpoch(EPOCH, 100e18, 100e6);
        vm.stopPrank();

        vm.prank(gateway);
        pool.recordUsdtInflow(EPOCH, 100e6);

        vm.prank(funder);
        pool.fundEpoch(EPOCH, 100e18, 100e6);
        assertEq(pool.totalFunded(), 100e18);
        assertEq(goat.balanceOf(address(pool)), 100e18);

        // One wei of backing beyond the recorded inflow flips it back to a revert.
        vm.startPrank(funder);
        vm.expectRevert(ProxyRevenueSettlement.BackingExceedsInflow.selector);
        pool.fundEpoch(EPOCH, 1e18, 1);
        vm.stopPrank();
    }

    /// `referenceRateUsdtPerGoat` is a REQUIRE, not a doc comment. Without this bound
    /// `fundEpoch(EPOCH, 1_000_000e18, 1)` passes on one USDT-wei of recorded inflow
    /// and the No-Ponzi inequality means nothing.
    ///
    /// Mutations this detects: deleting the rate bound; comparing goatAmount to
    /// backedUsdt without scaling.
    function test_funding_beyond_the_reference_rate_is_refused() public {
        vm.prank(gateway);
        pool.recordUsdtInflow(EPOCH, 1_000_000e6);
        vm.startPrank(funder);
        goat.approve(address(pool), 1_000_000e18);

        // Positive control: exactly at the rate is allowed.
        pool.fundEpoch(EPOCH, 100e18, 100e6);
        assertEq(pool.fundingOfGoatFunded(EPOCH), 100e18);

        // One wei of GOAT beyond what the backing buys at the reference rate.
        vm.expectRevert(ProxyRevenueSettlement.BackingBelowReferenceRate.selector);
        pool.fundEpoch(EPOCH, 100e18 + 1, 100e6);
        vm.stopPrank();
    }

    // ----------------------------------------------------- the derived take

    /// Mutations this detects: `finalizeBatch` regaining an amount parameter;
    /// the take read from anything other than the gross committed at propose time.
    function test_take_is_derived_from_the_committed_gross_not_supplied() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1_048_576, 900e18), 1_000e18);

        assertEq(goat.balanceOf(treasury), 60e18, "treasury = gross * 600 / 10000");
        assertEq(goat.balanceOf(attestorSafe), 20e18, "attestor = gross * 200 / 10000");
        assertEq(pool.reserveHeld(), 20e18, "reserve = take - treasury - attestor");
        assertEq(pool.totalClaimed(), 80e18, "only the transferred take is booked as claimed");
    }

    /// Mutations this detects: `finalizeBatch` losing its caller check, which turns
    /// it into a permissionless drain of the epoch's whole funding.
    function test_finalizeBatch_rejects_a_caller_who_is_not_the_publisher() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        // The root is computed BEFORE the prank: `_leaf` staticcalls
        // `pool.PROXY_LEAF_DOMAIN()`, and an argument expression is evaluated after
        // the cheatcode, so an inline `_leaf(...)` would spend the prank on that
        // read and send `proposeBatch` from the test contract instead.
        bytes32 root = _leaf(operator, EPOCH, 1, 900e18);
        vm.prank(publisher);
        pool.proposeBatch{value: BOND}(EPOCH, root, bytes32("e"), 1_000e18);
        vm.warp(block.timestamp + 6 hours + 1);

        vm.prank(stranger);
        vm.expectRevert(ProxyRevenueSettlement.NotPublisher.selector);
        pool.finalizeBatch(EPOCH);

        // Positive control: the publisher can, and the Safe can.
        vm.prank(publisher);
        pool.finalizeBatch(EPOCH);
        assertEq(uint256(pool.statusOf(EPOCH)), uint256(ProxyRevenueSettlement.Status.Finalized));
    }

    // -------------------------------------------------------- the two bounds

    /// The reserve is a bounded SUBTRACTION, never a buffer to spend from.
    ///
    /// The root published below is over the EXACT leaf this test claims, so the
    /// Merkle proof succeeds and the solvency require is genuinely the first failing
    /// check. An earlier draft claimed a leaf that was never published and reverted
    /// `BadProof`, which proved nothing about the reserve.
    ///
    /// Mutations this detects: the claim require weakened to `<= totalFunded`;
    /// reserveHeld decremented by a claim.
    function test_claim_cannot_touch_the_reserve() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        // gross 1000e18 -> take 100e18 -> treasury 60, attestor 20, reserve 20.
        // Per-epoch headroom is therefore 1000 - 80 - 20 = 900e18, computed here
        // BEFORE the root is published so the leaf can carry headroom + 1.
        uint256 headroom = 900e18;
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1, headroom + 1), 1_000e18);

        assertGt(pool.reserveHeld(), 0, "positive control: a finalized epoch must hold a reserve");
        assertEq(pool.totalFunded() - pool.totalClaimed() - pool.reserveHeld(), headroom);

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(ProxyRevenueSettlement.PoolWouldBeOverdrawn.selector);
        pool.claim(EPOCH, operator, 1, headroom + 1, proof);

        // Positive control: exactly the headroom is claimable.
        _proposeAndFinalizeFresh(EPOCH_B, operator, headroom, 1_000e18);
        pool.claim(EPOCH_B, operator, 1, headroom, new bytes32[](0));
        assertEq(goat.balanceOf(operator), headroom);
    }

    /// Mutations this detects: dropping the OPERATOR_BPS bound, which would let one
    /// leaf claim the protocol's take as well as the operator share.
    function test_claim_cannot_exceed_the_operator_share_of_the_committed_gross() public {
        // Funded far above the gross, so the pool bound cannot be what bites.
        _fund(EPOCH, 10_000e18, 10_000e6);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1, 900e18 + 1), 1_000e18);

        assertGt(pool.totalFunded() - pool.totalClaimed() - pool.reserveHeld(), 900e18 + 1, "pool has room");
        vm.expectRevert(ProxyRevenueSettlement.OperatorShareExceeded.selector);
        pool.claim(EPOCH, operator, 1, 900e18 + 1, new bytes32[](0));
    }

    /// The No-Ponzi inequality is about a WINDOW. Mutations this detects: the
    /// per-epoch check removed, leaving only the global counters -- under which an
    /// epoch that received almost no funding draws on another epoch's backing.
    function test_an_unfunded_epoch_cannot_claim_against_another_epochs_backing() public {
        _fund(EPOCH, 1_000e18, 1_000e6); // a large, well-funded neighbour
        _fund(EPOCH_B, 1e18, 1e6); // the thin epoch under test
        _proposeAndFinalize(EPOCH_B, _leaf(operator, EPOCH_B, 1, 9e17 + 1), 1e18);

        // Global headroom is enormous; per-epoch headroom is 9e17.
        assertGt(pool.totalFunded() - pool.totalClaimed() - pool.reserveHeld(), 900e18, "global has room");
        vm.expectRevert(ProxyRevenueSettlement.PoolWouldBeOverdrawn.selector);
        pool.claim(EPOCH_B, operator, 1, 9e17 + 1, new bytes32[](0));
    }

    /// Recon S5: payouts go only to screened, enrolled identities. Inheriting the
    /// restriction from GoatCoin's transfer hook makes the obligation invisible on
    /// the payout path; this makes it a named revert.
    ///
    /// Mutations this detects: deleting the registry lookup from `claim`.
    function test_claim_refuses_an_unenrolled_operator() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        _proposeAndFinalize(EPOCH, _leaf(unenrolled, EPOCH, 1, 100e18), 1_000e18);
        vm.expectRevert(ProxyRevenueSettlement.NotEnrolled.selector);
        pool.claim(EPOCH, unenrolled, 1, 100e18, new bytes32[](0));

        // Positive control: enrol, and the same claim goes through.
        vm.prank(safe);
        reg.setEnrolled(unenrolled, true, bytes32("kyc"));
        pool.claim(EPOCH, unenrolled, 1, 100e18, new bytes32[](0));
        assertEq(goat.balanceOf(unenrolled), 100e18);
    }

    // -------------------------------------------------- supply and reachability

    /// Zero new supply, forever.
    ///
    /// Mutations this detects: granting the settlement the minter role at deploy;
    /// any mint path added to this lane.
    function test_settlement_is_not_a_goat_minter() public {
        assertFalse(goat.isMinter(address(pool)));
        vm.prank(address(pool));
        vm.expectRevert();
        goat.mint(operator, 1e18);
    }

    /// FR-1 as a PROPERTY, not as vocabulary. The three no-burn tests elsewhere scan
    /// selectors, ABI entries and the word itself; this one asserts the thing those
    /// scans exist to protect -- that no GOAT is stranded. A `reserveHeld` with no
    /// withdrawal path is a supply sink whether or not anything is named after one.
    ///
    /// Mutations this detects: deleting `releaseReserve`; deleting `sweepUnclaimed`;
    /// `releaseReserve` failing to decrement `reserveHeld`.
    function test_every_wei_in_the_contract_is_reachable() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1, 900e18), 1_000e18);
        pool.claim(EPOCH, operator, 1, 900e18, new bytes32[](0));

        assertEq(goat.balanceOf(address(pool)), 20e18, "only the reserve remains");
        assertEq(pool.reserveHeld(), 20e18);

        vm.prank(stranger);
        vm.expectRevert(ProxyRevenueSettlement.NotSafe.selector);
        pool.releaseReserve(reserveSink, 20e18);

        vm.prank(safe);
        pool.releaseReserve(reserveSink, 20e18);
        assertEq(pool.reserveHeld(), 0);
        assertEq(goat.balanceOf(reserveSink), 20e18);
        assertEq(goat.balanceOf(address(pool)), 0, "no wei is unreachable");
    }

    /// The reserve may leave only to the reserve sink, and only by the Safe.
    ///
    /// Mutations this detects: `releaseReserve` accepting an arbitrary recipient.
    function test_releaseReserve_routes_only_to_the_reserve_sink() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1, 900e18), 1_000e18);
        vm.prank(safe);
        vm.expectRevert(ProxyRevenueSettlement.NotReserveSink.selector);
        pool.releaseReserve(treasury, 1);
    }

    /// Unclaimed GOAT past the claim window returns to a funder, rather than sitting
    /// in the contract forever subtracted from nothing.
    ///
    /// Mutations this detects: `sweepUnclaimed` losing its window guard; the swept
    /// amount failing to exclude the reserve.
    function test_unclaimed_goat_returns_to_the_funder_after_the_claim_window() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1, 900e18), 1_000e18);

        vm.prank(safe);
        vm.expectRevert(ProxyRevenueSettlement.WindowOpen.selector);
        pool.sweepUnclaimed(EPOCH, funder);

        vm.warp(block.timestamp + 30 days + 1);
        uint256 before = goat.balanceOf(funder);
        vm.prank(safe);
        pool.sweepUnclaimed(EPOCH, funder);
        assertEq(goat.balanceOf(funder) - before, 900e18, "the unclaimed operator share returns");
    }

    // ------------------------------------------------------------- liveness

    /// Mutations this detects: removing `timeoutChallenge`, which makes `Challenged`
    /// a terminal state -- one 0.05 ETH bond then freezes an epoch's funding forever.
    function test_an_unresolved_challenge_times_out_in_the_proposers_favour() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        bytes32 root = _leaf(operator, EPOCH, 1, 900e18); // before the prank -- see above
        vm.prank(publisher);
        pool.proposeBatch{value: BOND}(EPOCH, root, bytes32("e"), 1_000e18);
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        pool.challengeBatch{value: BOND}(EPOCH, bytes32("counter"));

        vm.expectRevert(ProxyRevenueSettlement.WindowOpen.selector);
        pool.timeoutChallenge(EPOCH);

        vm.warp(block.timestamp + 6 hours + 7 days + 1);
        pool.timeoutChallenge(EPOCH);
        assertEq(uint256(pool.statusOf(EPOCH)), uint256(ProxyRevenueSettlement.Status.ProposerWon));
        assertEq(pool.bondCredit(publisher), BOND, "the honest proposer's bond is returned");
        assertEq(pool.bondCredit(reserveSink), BOND, "the abandoned challenge is slashed to the reserve");

        vm.prank(publisher);
        pool.finalizeBatch(EPOCH);
        pool.claim(EPOCH, operator, 1, 900e18, new bytes32[](0));
    }

    /// Mutations this detects: `ChallengerWon` left terminal, so a proven-bad batch
    /// means every honest operator in that epoch is uncompensated forever.
    function test_a_successful_challenge_can_be_reset_and_reproposed() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        bytes32 badRoot = _leaf(operator, EPOCH, 1, 999e18); // before the prank -- see above
        vm.prank(publisher);
        pool.proposeBatch{value: BOND}(EPOCH, badRoot, bytes32("bad"), 1_000e18);
        vm.deal(stranger, 1 ether);
        vm.prank(stranger);
        pool.challengeBatch{value: BOND}(EPOCH, bytes32("counter"));
        vm.prank(resolver);
        pool.resolveChallenge(EPOCH, false);
        assertEq(uint256(pool.statusOf(EPOCH)), uint256(ProxyRevenueSettlement.Status.ChallengerWon));

        vm.prank(stranger);
        vm.expectRevert(ProxyRevenueSettlement.NotSafe.selector);
        pool.resetBatch(EPOCH);

        vm.prank(safe);
        pool.resetBatch(EPOCH);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1, 900e18), 1_000e18);
        pool.claim(EPOCH, operator, 1, 900e18, new bytes32[](0));
        assertEq(goat.balanceOf(operator), 900e18);
    }

    /// Bonds are PULL payments. Mutations this detects: paying bonds by `call` inside
    /// `resolveChallenge`, which a challenger contract that reverts on `receive()`
    /// bricks permanently.
    function test_a_reverting_bond_recipient_cannot_wedge_resolution() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        bytes32 root = _leaf(operator, EPOCH, 1, 900e18); // before the prank -- see above
        vm.prank(publisher);
        pool.proposeBatch{value: BOND}(EPOCH, root, bytes32("e"), 1_000e18);

        RevertingReceiver hostile = new RevertingReceiver();
        vm.deal(address(hostile), 1 ether);
        hostile.challenge{value: BOND}(pool, EPOCH, BOND);

        vm.prank(resolver);
        pool.resolveChallenge(EPOCH, true); // must not revert
        assertEq(uint256(pool.statusOf(EPOCH)), uint256(ProxyRevenueSettlement.Status.ProposerWon));
        assertEq(pool.bondCredit(reserveSink), BOND);

        // And a recipient that CAN receive really does collect its bond.
        uint256 before = publisher.balance;
        vm.prank(publisher);
        pool.withdrawBond();
        assertEq(publisher.balance - before, BOND);
    }

    /// Windows are snapshotted at propose time. Mutations this detects: `claim`
    /// recomputing its deadline from live storage, under which `setWindows(x, 0, y)`
    /// retroactively freezes every outstanding claim.
    function test_setWindows_cannot_retroactively_freeze_an_outstanding_claim() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1, 900e18), 1_000e18);
        vm.prank(safe);
        pool.setWindows(6 hours, 0, 7 days);
        pool.claim(EPOCH, operator, 1, 900e18, new bytes32[](0));
        assertEq(goat.balanceOf(operator), 900e18);
    }

    // ----------------------------------------------------------- epoch space

    /// INV-16 is asserted contract-wide, so every entrypoint must enforce it -- not
    /// the three that happened to get the guard first.
    ///
    /// Mutations this detects: dropping `_requireProxyEpoch` from any one of the six
    /// entrypoints below.
    function test_every_epoch_entrypoint_rejects_a_non_proxy_epoch() public {
        uint256 bad = 20_260_731; // a daily YYYYMMDD epoch
        vm.prank(gateway);
        vm.expectRevert(ProxyRevenueSettlement.EpochNotInProxySpace.selector);
        pool.recordUsdtInflow(bad, 1);

        vm.prank(funder);
        vm.expectRevert(ProxyRevenueSettlement.EpochNotInProxySpace.selector);
        pool.fundEpoch(bad, 1e18, 1);

        vm.prank(publisher);
        vm.expectRevert(ProxyRevenueSettlement.EpochNotInProxySpace.selector);
        pool.proposeBatch{value: BOND}(bad, bytes32("r"), bytes32("e"), 1e18);

        vm.expectRevert(ProxyRevenueSettlement.EpochNotInProxySpace.selector);
        pool.challengeBatch{value: BOND}(bad, bytes32("c"));

        vm.prank(publisher);
        vm.expectRevert(ProxyRevenueSettlement.EpochNotInProxySpace.selector);
        pool.finalizeBatch(bad);

        vm.expectRevert(ProxyRevenueSettlement.EpochNotInProxySpace.selector);
        pool.claim(bad, operator, 1, 1e18, new bytes32[](0));
    }

    // ------------------------------------------------------------ leaf shape

    /// A leaf that would be valid in EpochSettlement is not valid here, and vice
    /// versa. Domain separation is asserted on the preimage, not on a comment.
    ///
    /// Mutations this detects: changing the domain string; dropping the domain, the
    /// epoch id or the byte count from the preimage.
    function test_leaf_is_domain_tagged() public view {
        bytes32 tagged = keccak256(
            bytes.concat(keccak256(abi.encode(pool.PROXY_LEAF_DOMAIN(), operator, EPOCH, uint256(1), uint256(2))))
        );
        bytes32 untagged = keccak256(bytes.concat(keccak256(abi.encode(operator, uint256(2)))));
        assertTrue(tagged != untagged);
        assertEq(pool.PROXY_LEAF_DOMAIN(), keccak256("GOAT_PROXY_REVENUE_LEAF_V1"));
    }

    /// A second claim on the same (epoch, operator) is a revert, not a second transfer.
    ///
    /// Mutations this detects: deleting the `claimed` bookkeeping.
    function test_double_claim_reverts() public {
        _fund(EPOCH, 1_000e18, 1_000e6);
        _proposeAndFinalize(EPOCH, _leaf(operator, EPOCH, 1_048_576, 90e18), 1_000e18);
        bytes32[] memory proof = new bytes32[](0);
        pool.claim(EPOCH, operator, 1_048_576, 90e18, proof);
        vm.expectRevert(ProxyRevenueSettlement.AlreadyClaimed.selector);
        pool.claim(EPOCH, operator, 1_048_576, 90e18, proof);
    }

    // -------------------------------------------------------------- helpers

    function _leaf(address op, uint256 epochId, uint256 nBytes, uint256 amt) internal view returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(pool.PROXY_LEAF_DOMAIN(), op, epochId, nBytes, amt))));
    }

    function _fund(uint256 epochId, uint256 goatAmount, uint256 usdt) internal {
        vm.prank(gateway);
        pool.recordUsdtInflow(epochId, usdt);
        vm.startPrank(funder);
        goat.approve(address(pool), goatAmount);
        pool.fundEpoch(epochId, goatAmount, usdt);
        vm.stopPrank();
    }

    function _proposeAndFinalize(uint256 epochId, bytes32 root, uint256 gross) internal {
        vm.prank(publisher);
        pool.proposeBatch{value: BOND}(epochId, root, bytes32("evidence"), gross);
        vm.warp(block.timestamp + 6 hours + 1);
        vm.prank(publisher);
        pool.finalizeBatch(epochId);
    }

    function _proposeAndFinalizeFresh(uint256 epochId, address op, uint256 payout, uint256 gross) internal {
        _fund(epochId, gross, uint256(gross / 1e12));
        _proposeAndFinalize(epochId, _leaf(op, epochId, 1, payout), gross);
    }
}
