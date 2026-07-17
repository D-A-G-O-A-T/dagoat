// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {BuyDesk} from "../src/BuyDesk.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "openzeppelin-contracts/contracts/interfaces/draft-IERC6093.sol";

/// Allowance (wallet-direct) BuyDesk tests — the desk never custodies USDT;
/// it spends the owner's wallet USDT via allowance up to the cap the owner
/// approves. depth() == usdt.allowance(owner, desk); closing == approve 0.
contract BuyDeskTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    BuyDesk desk;
    MockUSDT usdt;
    address safe = makeAddr("safe");
    address founder = makeAddr("founder"); // owner: founder personal pilot
    address minter = makeAddr("minter");
    address alice = makeAddr("alice");
    address stranger = makeAddr("stranger");

    uint256 constant OWNER_WALLET = 100e6; // owner keeps USDT in their wallet
    uint256 constant CAP = 10e6; // committed buying power (allowance)

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        usdt = new MockUSDT();
        desk = new BuyDesk(founder, IERC20(address(usdt)), goat, reg);
        vm.startPrank(safe);
        goat.setMinter(minter, true);
        reg.setSystemAddress(address(desk), true);
        reg.setSystemAddress(founder, true);
        reg.setEnrolled(alice, true, bytes32(0));
        vm.stopPrank();
        // alice earned 1000 GOAT
        vm.prank(minter);
        goat.mint(alice, 1000e18);
        vm.prank(alice);
        goat.approve(address(desk), type(uint256).max);
        // Owner's USDT stays in the owner's own wallet. The desk gets a
        // committed cap of 10 USDT via allowance — no fund() step, no desk
        // custody. depth() then reads that allowance.
        usdt.mint(founder, OWNER_WALLET);
        vm.prank(founder);
        usdt.approve(address(desk), CAP);
    }

    function _openSession(uint256 cap) internal {
        vm.prank(founder);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), cap);
    }

    // --- constructor / bid defaults ---

    function test_bid_defaults_to_10000() public view {
        assertEq(desk.bid(), 10_000);
    }

    // --- depth() == owner allowance to the desk ---

    function test_depth_equals_owner_allowance() public view {
        assertEq(desk.depth(), CAP);
        assertEq(desk.depth(), usdt.allowance(founder, address(desk)));
    }

    function test_depth_zero_before_approve_then_equals_cap_after() public {
        // A brand-new desk the owner has not approved has zero depth.
        BuyDesk fresh = new BuyDesk(founder, IERC20(address(usdt)), goat, reg);
        assertEq(fresh.depth(), 0);
        // After approving, depth equals exactly the approved cap.
        vm.prank(founder);
        usdt.approve(address(fresh), 7e6);
        assertEq(fresh.depth(), 7e6);
    }

    function test_approve_zero_drops_depth_to_zero() public {
        assertEq(desk.depth(), CAP);
        vm.prank(founder);
        usdt.approve(address(desk), 0);
        assertEq(desk.depth(), 0);
    }

    // --- depth() stays truthful under an unlimited (max) approval ---
    // Regression (security review 2026-07-13): OZ ERC20 never decrements a
    // type(uint256).max allowance, so a naive depth()=allowance would stick at
    // ~1.16e71 forever and the Market UI would advertise a garbage buying
    // power. depth()=min(allowance, wallet balance) must instead track the
    // wallet — a real, decrementing number.
    function test_depth_under_unlimited_approval_tracks_wallet_not_max() public {
        vm.prank(founder);
        usdt.approve(address(desk), type(uint256).max);
        // depth is the owner's real wallet balance, never the max sentinel.
        assertEq(desk.depth(), usdt.balanceOf(founder));
        assertEq(desk.depth(), OWNER_WALLET);
        assertLt(desk.depth(), type(uint256).max);

        // and it still decrements as GOAT is bought (the wallet balance drops).
        _openSession(1000e18);
        vm.prank(alice);
        desk.sell(600e18); // 600 GOAT * 0.01 = 6 USDT out
        assertEq(desk.depth(), OWNER_WALLET - 6e6);
    }

    // depth() never advertises more than the owner can actually pay: a cap
    // committed above the wallet balance clamps to the balance.
    function test_depth_clamps_to_wallet_when_cap_exceeds_balance() public {
        vm.prank(founder);
        usdt.approve(address(desk), OWNER_WALLET + 500e6); // cap > wallet balance
        assertEq(desk.depth(), OWNER_WALLET);
    }

    // --- atomic swap: USDT from owner wallet, GOAT to owner ---

    function test_sell_moves_usdt_from_owner_wallet_and_goat_to_owner() public {
        _openSession(1000e18);
        uint256 founderUsdtBefore = usdt.balanceOf(founder);
        vm.prank(alice);
        desk.sell(600e18);
        // seller paid 600 GOAT * 0.01 USDT/GOAT = 6 USDT, sourced from owner's wallet
        assertEq(usdt.balanceOf(alice), 6e6);
        assertEq(usdt.balanceOf(founder), founderUsdtBefore - 6e6);
        // GOAT flows seller -> owner (the founder's public acquisition log)
        assertEq(goat.balanceOf(founder), 600e18);
        assertEq(goat.balanceOf(alice), 400e18);
        // the desk itself never custodies USDT
        assertEq(usdt.balanceOf(address(desk)), 0);
        // allowance (depth) decreased by usdtOut: 10 - 6 = 4 USDT
        assertEq(desk.depth(), 4e6);
    }

    function test_depth_decreases_by_usdtOut_after_sell() public {
        _openSession(1000e18);
        uint256 depthBefore = desk.depth();
        vm.prank(alice);
        desk.sell(250e18); // 250 GOAT * 0.01 = 2.5 USDT
        assertEq(desk.depth(), depthBefore - 2_500_000);
    }

    function test_desk_never_custodies_usdt() public {
        _openSession(1000e18);
        assertEq(usdt.balanceOf(address(desk)), 0);
        vm.prank(alice);
        desk.sell(600e18);
        assertEq(usdt.balanceOf(address(desk)), 0);
    }

    function test_sell_emits_Sold_event() public {
        _openSession(1000e18);
        vm.expectEmit(true, true, false, true, address(desk));
        emit BuyDesk.Sold(1, alice, 600e18, 6e6);
        vm.prank(alice);
        desk.sell(600e18);
    }

    // --- allowance / balance revert paths ---

    function test_sell_reverts_insufficient_allowance_when_cap_never_set() public {
        // A fresh desk the owner never approved: allowance is 0.
        BuyDesk fresh = new BuyDesk(founder, IERC20(address(usdt)), goat, reg);
        vm.prank(alice);
        goat.approve(address(fresh), type(uint256).max);
        vm.prank(founder);
        fresh.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 1000e18);

        // OZ parameterized custom error -> match on selector only.
        vm.expectPartialRevert(IERC20Errors.ERC20InsufficientAllowance.selector);
        vm.prank(alice);
        fresh.sell(600e18);
        // whole tx reverted: no session-sold state written
        assertEq(fresh.soldInSession(1, alice), 0);
    }

    function test_sell_reverts_insufficient_allowance_when_cap_exhausted() public {
        // Lower the committed cap so a second sell exhausts the allowance
        // while the seller still holds enough GOAT for the GOAT leg.
        vm.prank(founder);
        usdt.approve(address(desk), 5e6);
        _openSession(2000e18);

        vm.prank(alice);
        desk.sell(400e18); // 4 USDT out; allowance 5 -> 1
        assertEq(desk.depth(), 1e6);

        // next sell needs 4 USDT but only 1 USDT of allowance remains
        vm.expectPartialRevert(IERC20Errors.ERC20InsufficientAllowance.selector);
        vm.prank(alice);
        desk.sell(400e18);
        // per-account sold reflects only the first, successful sale
        assertEq(desk.soldInSession(1, alice), 400e18);
    }

    function test_sell_reverts_insufficient_balance_when_wallet_short() public {
        _openSession(1000e18);
        // Owner commits a large cap but drains their wallet: the cap is a
        // committed intent, not a locked reserve (spec §3 honest residue).
        vm.startPrank(founder);
        usdt.approve(address(desk), 1000e6);
        usdt.transfer(stranger, usdt.balanceOf(founder));
        vm.stopPrank();
        assertEq(usdt.balanceOf(founder), 0);
        // depth() = min(allowance, wallet balance): the 1000 USDT allowance is
        // still committed, but the drained wallet means the desk honestly
        // reports 0 buying power (it cannot pay anyone) rather than the
        // over-committed cap.
        assertEq(desk.depth(), 0);

        vm.expectPartialRevert(IERC20Errors.ERC20InsufficientBalance.selector);
        vm.prank(alice);
        desk.sell(600e18);
        assertEq(desk.soldInSession(1, alice), 0);
    }

    // --- owner cannot sell ---

    function test_owner_cannot_sell() public {
        _openSession(1000e18);
        // OwnerCannotSell is checked first, before any transfer.
        vm.expectRevert(BuyDesk.OwnerCannotSell.selector);
        vm.prank(founder);
        desk.sell(1e18);
    }

    // --- enrollment gate ---

    function test_sell_requires_enrollment() public {
        _openSession(1000e18);
        vm.expectRevert(BuyDesk.NotEnrolled.selector);
        vm.prank(stranger);
        desk.sell(1e18);
    }

    // --- session gating incl. closeSession ---

    function test_sell_requires_open_session() public {
        vm.expectRevert(BuyDesk.NoActiveSession.selector);
        vm.prank(alice);
        desk.sell(1e18);
    }

    function test_session_expires() public {
        _openSession(1000e18);
        vm.warp(block.timestamp + 1 days + 1);
        vm.expectRevert(BuyDesk.NoActiveSession.selector);
        vm.prank(alice);
        desk.sell(1e18);
    }

    function test_closeSession_ends_session_early() public {
        _openSession(1000e18);
        vm.prank(alice);
        desk.sell(1e18); // works while open
        vm.prank(founder);
        desk.closeSession();
        vm.expectRevert(BuyDesk.NoActiveSession.selector);
        vm.prank(alice);
        desk.sell(1e18);
    }

    function test_currentSession_zeros_when_none() public view {
        (uint256 id, uint64 start, uint64 end, uint256 cap) = desk.currentSession();
        assertEq(id, 0);
        assertEq(start, 0);
        assertEq(end, 0);
        assertEq(cap, 0);
    }

    function test_openSession_onlyOwner() public {
        vm.expectRevert(BuyDesk.NotOwner.selector);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), 1000e18);
    }

    function test_closeSession_onlyOwner() public {
        _openSession(1000e18);
        vm.expectRevert(BuyDesk.NotOwner.selector);
        desk.closeSession();
    }

    // --- per-account session cap ---

    function test_sell_respects_per_account_cap() public {
        _openSession(500e18);
        vm.prank(alice);
        desk.sell(500e18);
        vm.expectRevert(BuyDesk.CapExceeded.selector);
        vm.prank(alice);
        desk.sell(1e18);
    }

    // --- ZeroPayout boundary ---

    function test_sell_zero_or_dust_reverts_at_boundary() public {
        _openSession(1000e18);
        vm.expectRevert(BuyDesk.ZeroPayout.selector);
        vm.prank(alice);
        desk.sell(0);
        vm.expectRevert(BuyDesk.ZeroPayout.selector);
        vm.prank(alice);
        desk.sell(1e14 - 1); // floors to 0 USDT at bid=10_000
        // smallest sellable unit still works: 1e14 GOAT wei = 1 micro-USDT
        vm.prank(alice);
        desk.sell(1e14);
        assertEq(usdt.balanceOf(alice), 1);
    }

    // --- setBid ---

    function test_setBid_onlyOwner() public {
        vm.expectRevert(BuyDesk.NotOwner.selector);
        desk.setBid(20_000);
    }

    function test_setBid_emits_BidSet_and_updates_bid() public {
        vm.expectEmit(true, true, true, true, address(desk));
        emit BuyDesk.BidSet(10_000, 20_000);
        vm.prank(founder);
        desk.setBid(20_000);
        assertEq(desk.bid(), 20_000);
    }

    function test_setBid_zero_closes_desk_for_value() public {
        _openSession(1000e18);
        vm.prank(founder);
        desk.setBid(0);
        vm.expectRevert(BuyDesk.ZeroPayout.selector);
        vm.prank(alice);
        desk.sell(600e18);
    }

    function test_setBid_not_retroactive_uses_current_bid_at_sell_time() public {
        _openSession(1000e18);
        vm.prank(alice);
        desk.sell(100e18); // at bid 10_000 -> 1e6 USDT
        assertEq(usdt.balanceOf(alice), 1e6);
        vm.prank(founder);
        desk.setBid(20_000);
        vm.prank(alice);
        desk.sell(100e18); // at new bid 20_000 -> 2e6 USDT
        assertEq(usdt.balanceOf(alice), 3e6);
    }
}
