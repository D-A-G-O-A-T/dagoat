// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {ProxyRevenueSettlement} from "../src/proxy/ProxyRevenueSettlement.sol";

contract ProxyRevenueHandler is Test {
    ProxyRevenueSettlement public pool;
    GoatCoin public goat;
    address public funder;
    address public gateway;
    address[] public operators;

    uint256 constant EPOCH = 8_000_000_020_664;

    uint256 public ghostFunded;
    uint256 public ghostClaimed;
    uint256 public ghostTaken;
    /// A fresh epoch per claim, so no call can collide with an already-published
    /// root and be silently skipped.
    uint256 public nextEpoch = 8_000_000_030_000;

    constructor(ProxyRevenueSettlement p, GoatCoin g, address f, address gw, address[] memory ops) {
        pool = p;
        goat = g;
        funder = f;
        gateway = gw;
        operators = ops;
    }

    /// Iterating every epoch the handler touched, so the per-epoch invariant does
    /// not have to guess which ones exist.
    function touchedEpochs() external view returns (uint256 first, uint256 last) {
        return (8_000_000_030_000, nextEpoch);
    }

    /// PRE-conditions are bounded so that no call can revert. Under
    /// `fail_on_revert = true` a revert fails the suite, and the foundry.toml
    /// comment is explicit that the fix is tightening pre-conditions, never
    /// discarding post-conditions. An earlier draft drew a mean of ~500 000e18
    /// against a 10 000 000e18 seed and exhausted the funder after ~20 of the 25
    /// calls in a run.
    function fund(uint96 rawAmount) external {
        uint256 amount = uint256(rawAmount) % 100_000e18;
        if (amount == 0) return;
        if (amount > goat.balanceOf(funder)) return; // the funder cannot spend what it does not hold
        uint256 usdt = amount / 1e12 + 1;
        vm.prank(gateway);
        pool.recordUsdtInflow(EPOCH, usdt);
        vm.startPrank(funder);
        goat.approve(address(pool), amount);
        pool.fundEpoch(EPOCH, amount, usdt);
        vm.stopPrank();
        ghostFunded += amount;
    }

    /// Claims through a single-leaf root so the proof is trivially valid: the
    /// property under test is the solvency require, not the Merkle library.
    ///
    /// The handler funds the epoch it claims against. An earlier draft funded
    /// `8_000_000_020_664` and claimed against a salted epoch whose `goatFunded` was
    /// zero -- which made the suite DEMONSTRATE the cross-epoch draw and then certify
    /// it, because the only bound it checked was the global one.
    function claimSome(uint8 opIdx, uint96 rawAmount, uint16 takeSalt) external {
        address op = operators[opIdx % operators.length];
        uint256 gross = uint256(rawAmount) % 10_000e18;
        if (gross < 10_000) return; // below this the derived take rounds to dust
        if (gross > goat.balanceOf(funder)) return;

        uint256 epoch = nextEpoch;
        nextEpoch += 1;
        if (epoch >= pool.PROXY_EPOCH_CEILING()) return;

        // Fund THIS epoch, so the per-epoch bound is the one under test.
        uint256 usdt = gross / 1e12 + 1;
        vm.prank(gateway);
        pool.recordUsdtInflow(epoch, usdt);
        vm.startPrank(funder);
        goat.approve(address(pool), gross);
        pool.fundEpoch(epoch, gross, usdt);
        vm.stopPrank();
        ghostFunded += gross;

        // A non-zero take on every run: an earlier draft always finalized with a
        // take of zero, so the take path was never exercised by the invariant at all.
        uint256 payout = (gross * pool.OPERATOR_BPS()) / pool.BPS_DENOM();
        payout = payout - (uint256(takeSalt) % (payout / 2 + 1));
        if (payout == 0) return;

        bytes32 leaf =
            keccak256(bytes.concat(keccak256(abi.encode(pool.PROXY_LEAF_DOMAIN(), op, epoch, uint256(1), payout))));
        vm.deal(pool.publisher(), 1 ether);
        vm.startPrank(pool.publisher());
        pool.proposeBatch{value: pool.proposerBond()}(epoch, leaf, bytes32("e"), gross);
        vm.warp(block.timestamp + pool.challengeWindow() + 1);
        pool.finalizeBatch(epoch);
        vm.stopPrank();
        ghostTaken += (gross * pool.TAKE_BPS()) / pool.BPS_DENOM();

        bytes32[] memory proof = new bytes32[](0);
        pool.claim(epoch, op, 1, payout, proof);
        ghostClaimed += payout;
    }
}

contract ProxyRevenueSolvencyTest is Test {
    GoatCoin goat;
    EnrollmentRegistry reg;
    ProxyRevenueSettlement pool;
    ProxyRevenueHandler handler;

    address safe = makeAddr("safe");
    address funder = makeAddr("funder");
    address publisher = makeAddr("publisher");
    address gateway = makeAddr("gateway");
    address treasury = makeAddr("treasury");
    address attestorSafe = makeAddr("attestorSafe");
    address reserveSink = makeAddr("reserveSink");

    uint256 constant SEED = 10_000_000e18;

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        pool = new ProxyRevenueSettlement(_config());

        address[] memory ops = new address[](4);
        vm.startPrank(safe);
        for (uint256 i = 0; i < 4; i++) {
            ops[i] = address(uint160(0xB0 + i));
            reg.setEnrolled(ops[i], true, bytes32("kyc"));
        }
        reg.setSystemAddress(address(pool), true);
        // Every address the take can reach must be enrolled, or the first
        // `finalizeBatch` reverts TransferRestricted and `fail_on_revert = true`
        // fails the suite for a reason unrelated to solvency.
        reg.setEnrolled(funder, true, bytes32("kyc"));
        reg.setEnrolled(treasury, true, bytes32("kyc"));
        reg.setEnrolled(attestorSafe, true, bytes32("kyc"));
        reg.setEnrolled(reserveSink, true, bytes32("kyc"));
        goat.setMinter(safe, true);
        goat.mint(funder, SEED); // the ONLY mint in this suite: seeding the funder
        vm.stopPrank();

        handler = new ProxyRevenueHandler(pool, goat, funder, gateway, ops);
        targetContract(address(handler));

        // ONE funded epoch and ONE landed claim, driven through the handler itself,
        // before the fuzzer starts.
        //
        // This is not decoration and it is not a weakening. Foundry asserts every
        // invariant after EVERY call of a run, including the first, so a suite whose
        // vacuity guard demands `ghostClaimed > 0` fails on call 1 of run 1 whenever
        // that call is `fund` -- a red that says nothing about solvency. Priming
        // through the handler's own entrypoints keeps the guard doing the job it was
        // written for: it is a POSITIVE CONTROL proving `claimSome`'s body reaches a
        // real claim rather than returning early on every input, and proving the
        // per-epoch invariant below has at least one epoch to iterate. If either
        // handler path is broken, `setUp` itself reverts and the suite is red.
        handler.fund(uint96(1_000e18));
        handler.claimSome(0, uint96(1_000e18), 0);
        assertGt(handler.ghostClaimed(), 0, "the handler could not land a claim even once");
    }

    /// THE No-Ponzi invariant, as a contract-level bound rather than a policy.
    ///
    /// Written `funded >= claimed + reserve` and not `claimed <= funded - reserve`
    /// so the ASSERTION itself cannot underflow and mask the state it must catch.
    ///
    /// Mutations this detects:
    /// - the claim require weakened from `<= totalFunded - reserveHeld` to `<= totalFunded`
    /// - reserveHeld decremented by a claim
    /// - totalClaimed incremented after the transfer instead of before
    function invariant_fundedCoversClaimedPlusReserve() public view {
        assertGe(
            pool.totalFunded(), pool.totalClaimed() + pool.reserveHeld(), "No-Ponzi: claimed + reserve exceeded funded"
        );
    }

    /// The SAME inequality, per window. Written separately because the global form
    /// is a strictly weaker property: with only the global counters, an epoch that
    /// received no funding can be paid out of a funded neighbour's backing and every
    /// global assertion stays green.
    ///
    /// Mutations this detects: the per-epoch bound removed from `claim`; the
    /// per-epoch `goatClaimed` incremented in `finalizeBatch` but not in `claim`.
    function invariant_everyEpochCoversItsOwnClaims() public view {
        (uint256 first, uint256 last) = handler.touchedEpochs();
        uint256 checked = 0;
        for (uint256 e = first; e < last; e++) {
            (uint256 funded,,, uint256 claimedWei, uint256 reserved) = pool.fundingOf(e);
            if (funded == 0 && claimedWei == 0) continue;
            assertGe(funded, claimedWei + reserved, "an epoch paid out more than it was funded");
            checked += 1;
        }
        assertGt(checked, 0, "no epoch was ever funded -- this invariant is vacuous");
    }

    /// Mutations this detects: the pool paying out of a balance it did not receive.
    function invariant_poolBalanceCoversUnclaimed() public view {
        uint256 unclaimed = pool.totalFunded() - pool.totalClaimed();
        assertGe(goat.balanceOf(address(pool)), unclaimed, "pool cannot honour outstanding claims");
    }

    /// FR-1 as a balance identity rather than as vocabulary: everything the contract
    /// holds is still reachable by somebody. Mutations this detects: any path that
    /// moves GOAT to an address with no withdrawal route, or a `reserveHeld` that
    /// double-counts.
    function invariant_poolHoldsExactlyWhatIsStillReachable() public view {
        uint256 reachable = pool.totalFunded() - pool.totalClaimed();
        assertEq(goat.balanceOf(address(pool)), reachable, "GOAT is stranded in the settlement contract");
        assertGe(reachable, pool.reserveHeld(), "the reserve must be inside what the pool still holds");
    }

    /// Mutations this detects: any mint path reintroduced on this lane. The seed
    /// mint happens in setUp, before the run.
    function invariant_totalSupplyNeverGrowsDuringSettlement() public view {
        assertEq(goat.totalSupply(), SEED, "proxy settlement minted new supply");
    }

    /// Vacuity guard. `fail_on_revert = true` plus over-tight handler guards can
    /// produce a run in which nothing ever happened, and three passing invariants
    /// over an empty state space prove nothing.
    function invariant_handlerActuallyMovedValue() public view {
        assertGt(handler.ghostFunded(), 0, "no funding call ever landed -- the run is vacuous");
        assertGt(handler.ghostClaimed(), 0, "no claim ever landed -- the invariant is vacuous");
        assertGt(handler.ghostTaken(), 0, "the take path was never exercised -- see the 0-take draft");
    }

    function _config() internal returns (ProxyRevenueSettlement.Config memory) {
        return ProxyRevenueSettlement.Config({
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
            resolver: makeAddr("resolver"),
            watcher: makeAddr("watcher"),
            challengeWindow: 6 hours,
            claimWindow: 30 days,
            resolveWindow: 7 days,
            proposerBond: 0.05 ether,
            challengerBond: 0.05 ether,
            referenceRateUsdtPerGoat: 1e6
        });
    }
}
