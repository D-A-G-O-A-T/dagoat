// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {BuyDesk} from "../src/BuyDesk.sol";
import {ProxyRevenueTreasury} from "../src/proxy/ProxyRevenueTreasury.sol";
import {ProxyRevenueSettlement} from "../src/proxy/ProxyRevenueSettlement.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";

/// Option B of the funding path: a custodian that holds consumer USDT, owns an
/// UNMODIFIED `BuyDesk`, and is inert until the Policy Safe arms it once.
///
/// `ProxyRevenueSettlement` is imported even though the treasury's own header
/// never names it in a test signature: `test_option_b_can_be_armed_on_an_option_a_settlement`
/// constructs one, and the settlement's `Config` struct and its
/// `BackingExceedsInflow` selector are both reached through the type. Without the
/// import this file does not compile.
contract ProxyRevenueTreasuryTest is Test {
    GoatCoin goat;
    EnrollmentRegistry registry;
    MockUSDT usdt;
    BuyDesk desk;
    ProxyRevenueTreasury treasury;

    address safe = address(0xA11CE);
    address seller = address(0x5E11);

    function setUp() public {
        vm.startPrank(safe);
        // The registry MUST be constructed before the token that stores it. An
        // earlier draft had these two lines the other way round, which handed
        // GoatCoin the zero address and made every transfer check -- including the
        // `goat.mint` three lines below -- call into nothing.
        registry = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, registry);
        usdt = new MockUSDT();
        treasury = new ProxyRevenueTreasury(safe, address(usdt), address(goat));
        registry.setEnrolled(address(treasury), true, bytes32("kyc-treasury"));
        registry.setEnrolled(seller, true, bytes32("kyc-seller"));
        desk = new BuyDesk(address(treasury), usdt, goat, registry);
        goat.setMinter(safe, true);
        goat.mint(seller, 1_000e18);
        vm.stopPrank();
        usdt.mint(address(treasury), 100_000e6);
        vm.prank(safe);
        treasury.bindDeskOnce(address(desk));
    }

    /// The treasury spends only what governance approved, never its whole balance
    /// -- the desk's spending cap IS the allowance, and depth() reports it.
    ///
    /// Mutations this detects: `setDeskAllowance` approving `type(uint256).max`
    /// instead of `amount`; approving the treasury's whole USDT balance; dropping
    /// the `forceApprove` to zero so a closed bid still reports depth.
    function test_desk_depth_is_bounded_by_the_approved_amount() public {
        vm.prank(safe);
        treasury.setDeskAllowance(10_000e6);
        assertEq(desk.depth(), 10_000e6);
        vm.prank(safe);
        treasury.setDeskAllowance(0);
        assertEq(desk.depth(), 0);
    }

    /// The desk's governance calls are `onlyOwner` and the OWNER IS THIS CONTRACT,
    /// so the Policy Safe reaches them only through the treasury's forwarders.
    /// Both halves are asserted, and the first is the defect that made the two
    /// market-buy tests below fail before the forwarders existed.
    ///
    /// Mutations this detects: dropping `onlySafe` from any of the three
    /// forwarders; deleting the forwarders entirely (the desk then has no path to
    /// an open session and can never buy); a forwarder that silently no-ops
    /// instead of reaching the desk -- the positive control reads the desk's own
    /// state back, not the treasury's.
    function test_desk_operation_is_owner_only_and_routes_through_the_safe() public {
        assertEq(desk.owner(), address(treasury), "the treasury must own the desk it operates");

        // Directly: refused, even for the Policy Safe.
        vm.expectRevert(BuyDesk.NotOwner.selector);
        vm.prank(safe);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 1e18);

        // Through the treasury: refused for a stranger, on all three forwarders.
        vm.expectRevert(ProxyRevenueTreasury.NotSafe.selector);
        vm.prank(seller);
        treasury.openDeskSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 1e18);
        vm.expectRevert(ProxyRevenueTreasury.NotSafe.selector);
        vm.prank(seller);
        treasury.setDeskBid(1);
        vm.expectRevert(ProxyRevenueTreasury.NotSafe.selector);
        vm.prank(seller);
        treasury.closeDeskSession();

        // Positive control: the Safe can, and the DESK's own state moves.
        vm.startPrank(safe);
        treasury.setDeskBid(20_000);
        treasury.openDeskSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 1e18);
        vm.stopPrank();
        assertEq(desk.bid(), 20_000, "the bid forwarder did not reach the desk");
        (uint256 id,,,) = desk.currentSession();
        assertGt(id, 0, "no session is open, so no sale could ever happen");

        vm.prank(safe);
        treasury.closeDeskSession();
        (uint256 closed,,,) = desk.currentSession();
        assertEq(closed, 0, "the close forwarder did not reach the desk");
    }

    /// Mutations this detects: binding a desk whose owner is not this treasury, so
    /// the bought GOAT lands elsewhere; `setDeskAllowance` approving an address
    /// other than the bound desk, so the sale cannot draw the USDT at all.
    ///
    /// The session is opened THROUGH the treasury, not on the desk directly. That
    /// is not a stylistic choice: the desk's `openSession` is `onlyOwner` and the
    /// owner is the treasury, so a direct `desk.openSession` from the Safe reverts
    /// `BuyDesk.NotOwner` -- which is exactly how the missing forwarders were found.
    function test_market_buy_lands_goat_on_the_treasury() public {
        vm.startPrank(safe);
        treasury.setDeskAllowance(10_000e6);
        treasury.openDeskSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 1_000e18);
        vm.stopPrank();
        vm.startPrank(seller);
        goat.approve(address(desk), 100e18);
        desk.sell(100e18);
        vm.stopPrank();
        assertEq(goat.balanceOf(address(treasury)), 100e18);
        assertEq(usdt.balanceOf(seller), 100e18 * desk.bid() / 1e18);
    }

    /// USDT out can never exceed the approval, which is the on-chain form of
    /// "USDT out <= real funding in".
    ///
    /// The allowance must be set BELOW what the sale actually costs, or the sale
    /// simply succeeds and the assertion never fires. `BuyDesk.sol:66` initialises
    /// `bid = 10_000` and `:137` computes `usdtOut = goatAmount * bid / 1e18`, so
    /// selling 1 000e18 GOAT costs **10e6 USDT**, not 1 000e6 -- an earlier draft
    /// approved 500e6 against a 10e6 spend and expected a revert that could not
    /// happen. And the revert is asserted by SELECTOR: a bare `vm.expectRevert()`
    /// would have swallowed the unrelated zero-registry revert this same `setUp` used
    /// to produce, hiding two defects behind one green line.
    ///
    /// Mutations this detects: `setDeskAllowance` rounding an approval up, or
    /// approving more than `amount`; the treasury handing the desk an unbounded
    /// approval once and never reducing it.
    function test_usdt_out_never_exceeds_the_approval() public {
        uint256 cost = 1_000e18 * desk.bid() / 1e18; // 10e6 at the initial bid
        vm.startPrank(safe);
        treasury.setDeskAllowance(cost - 1);
        treasury.openDeskSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 1_000e18);
        vm.stopPrank();
        vm.startPrank(seller);
        goat.approve(address(desk), 1_000e18);
        vm.expectRevert(
            abi.encodeWithSignature(
                "ERC20InsufficientAllowance(address,uint256,uint256)", address(desk), cost - 1, cost
            )
        );
        desk.sell(1_000e18);
        vm.stopPrank();
        assertEq(goat.balanceOf(address(treasury)), 0);

        // Positive control: one more wei of allowance and the same sale goes through.
        vm.prank(safe);
        treasury.setDeskAllowance(cost);
        vm.startPrank(seller);
        desk.sell(1_000e18);
        vm.stopPrank();
        assertEq(goat.balanceOf(address(treasury)), 1_000e18);
    }

    /// The gate: the treasury cannot fund settlement until the Policy Safe arms it,
    /// and there is no path for anyone else to arm it.
    ///
    /// Mutations this detects: initialising `armed` to true; dropping the
    /// `if (!armed) revert NotArmed()` guard from `fundSettlement`; moving that
    /// guard below a check that would revert first and mask it.
    function test_funding_is_refused_until_armed() public {
        vm.expectRevert(ProxyRevenueTreasury.NotArmed.selector);
        vm.prank(safe);
        treasury.fundSettlement(address(0x1), 8_000_000_020_664, 1e18, 1);
    }

    /// Mutations this detects: dropping `onlySafe` from `arm()`; widening the
    /// modifier to accept the desk, the bound settlement, or any enrolled account.
    function test_only_safe_can_arm() public {
        vm.expectRevert(ProxyRevenueTreasury.NotSafe.selector);
        vm.prank(seller);
        treasury.arm();
    }

    /// The gate is ONE-WAY and it defaults OFF. Both halves are asserted, and the
    /// absence of a reverse path is asserted at the ABI, not merely in prose: an
    /// `arm()` that a later governance call can undo is a switch, not a gate.
    ///
    /// POSITIVE CONTROL FIRST, for the same reason as the FR-1 probe below: an
    /// `assertFalse(ok)` on a raw call is true of any address that implements
    /// nothing at all.
    ///
    /// Mutations this detects: `armed = true` in the constructor; replacing
    /// `AlreadyArmed` with a silent no-op re-arm; adding `disarm()` or
    /// `setArmed(bool)` in any later revision.
    function test_arm_is_one_way_and_defaults_off() public {
        assertFalse(treasury.armed(), "armed must be OFF at deploy");

        vm.prank(safe);
        treasury.arm();
        assertTrue(treasury.armed());

        // Re-arming is refused rather than silently repeated, and the flag survives.
        vm.expectRevert(ProxyRevenueTreasury.AlreadyArmed.selector);
        vm.prank(safe);
        treasury.arm();
        assertTrue(treasury.armed(), "a refused re-arm must not clear the flag");

        (bool live, bytes memory liveRet) = address(treasury).call(abi.encodeWithSignature("armed()"));
        assertTrue(live, "probe control failed: the treasury does not answer a selector it has");
        assertGt(liveRet.length, 0, "probe control failed: no return data from a real view");

        vm.prank(safe);
        (bool disarmed,) = address(treasury).call(abi.encodeWithSignature("disarm()"));
        assertFalse(disarmed, "a disarm entrypoint exists");
        vm.prank(safe);
        (bool setArmed,) = address(treasury).call(abi.encodeWithSignature("setArmed(bool)", false));
        assertFalse(setArmed, "an armed-flag setter exists");
        assertTrue(treasury.armed(), "the flag moved despite both probes failing");
    }

    /// INV-13 at the treasury: the custodian is not a minter and has no route to
    /// becoming one through this task's code. The control proves `isMinter` is a
    /// question this fixture can answer YES to, so the two NOs are not vacuous.
    ///
    /// Mutations this detects: a `setUp` or deploy script that grants the treasury
    /// the minter role; the treasury acquiring GOAT by issuance rather than by
    /// buying it from a willing counterparty at the posted bid.
    function test_treasury_holds_no_minter_role() public view {
        assertTrue(goat.isMinter(safe), "control: the Safe IS a minter in this fixture");
        assertFalse(goat.isMinter(address(treasury)), "the treasury must never hold the minter role");
        assertFalse(goat.isMinter(address(desk)), "the desk it owns must never hold it either");
    }

    /// FR-1 again, at the treasury.
    ///
    /// POSITIVE CONTROL FIRST: `assertFalse(ok)` on a raw call is true of any address
    /// with no such function -- including `address(0)`. The control proves the probe
    /// is pointed at a live contract that answers calls it *does* implement.
    ///
    /// Mutations this detects: adding a supply-destruction entrypoint to the
    /// treasury under any signature that takes one amount.
    function test_treasury_has_no_burn_selector() public {
        (bool live, bytes memory liveRet) = address(treasury).call(abi.encodeWithSignature("armed()"));
        assertTrue(live, "probe control failed: the treasury does not answer a selector it has");
        assertGt(liveRet.length, 0, "probe control failed: no return data from a real view");

        (bool ok, bytes memory ret) = address(treasury).call(abi.encodeWithSignature("burn(uint256)", uint256(1)));
        assertFalse(ok);
        assertEq(ret.length, 0);
    }

    /// Option B must be armable on a settlement that was deployed for Option A.
    /// With `funder` immutable, it was not: the only route to `funder == treasury`
    /// was a redeploy, which orphans every published root and every unclaimed epoch,
    /// so "gated, not deferred" would have been false.
    ///
    /// Mutations this detects: making `isFunder` immutable or removing `setFunder`;
    /// the treasury reading a single `funder()` address instead of the one-way
    /// funder set; dropping the `SettlementMismatch` guard so the treasury would
    /// approve GOAT to a settlement that cannot pull it.
    function test_option_b_can_be_armed_on_an_option_a_settlement() public {
        ProxyRevenueSettlement settlement = _deploySettlementWithFounderFunder();
        assertFalse(settlement.isFunder(address(treasury)), "not a funder at deploy");

        vm.prank(safe);
        settlement.setFunder(address(treasury));
        assertTrue(settlement.isFunder(address(treasury)), "the Safe can add a funder without redeploying");

        vm.prank(safe);
        treasury.arm();
        // And the treasury's own mismatch guard now passes for this settlement.
        vm.prank(safe);
        vm.expectRevert(ProxyRevenueSettlement.BackingExceedsInflow.selector);
        treasury.fundSettlement(address(settlement), 8_000_000_020_664, 1e18, 1);
    }

    /// A settlement wired for Option A: the FOUNDER is the funder at deploy, and the
    /// treasury is not.
    function _deploySettlementWithFounderFunder() internal returns (ProxyRevenueSettlement) {
        address founder = address(0xF00);
        return new ProxyRevenueSettlement(
            ProxyRevenueSettlement.Config({
                safe: safe,
                goat: address(goat),
                registry: address(registry),
                treasury: address(0xA1),
                attestorSafe: address(0xA2),
                reserveSink: address(0xA3),
                funder: founder,
                publisher: address(0xA4),
                gateway: address(0xA5),
                usdtTreasury: address(0xA6),
                resolver: address(0xA7),
                watcher: address(0xA8),
                challengeWindow: 6 hours,
                claimWindow: 30 days,
                resolveWindow: 7 days,
                proposerBond: 0.05 ether,
                challengerBond: 0.05 ether,
                referenceRateUsdtPerGoat: 1e6
            })
        );
    }
}
