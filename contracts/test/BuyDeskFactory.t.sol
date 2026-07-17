// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {BuyDesk} from "../src/BuyDesk.sol";
import {BuyDeskFactory} from "../src/BuyDeskFactory.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract BuyDeskFactoryTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    MockUSDT usdt;
    BuyDeskFactory factory;

    address safe = makeAddr("safe");
    address minter = makeAddr("minter");
    address ownerA = makeAddr("ownerA"); // enrolled worker-owner (dual role)
    address ownerB = makeAddr("ownerB"); // pure donor, NOT enrolled at setUp
    address workerA = makeAddr("workerA");
    address workerB = makeAddr("workerB");
    address solo = makeAddr("solo");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        usdt = new MockUSDT();
        factory = new BuyDeskFactory(IERC20(address(usdt)), goat, reg);

        vm.startPrank(safe);
        goat.setMinter(minter, true);
        reg.setEnrolled(ownerA, true, bytes32(0));
        reg.setEnrolled(workerA, true, bytes32(0));
        reg.setEnrolled(workerB, true, bytes32(0));
        // ownerB intentionally left NOT enrolled to exercise the
        // pure-donor gating case.
        vm.stopPrank();
    }

    /// Allowance model: the owner keeps USDT in their wallet and commits a
    /// cap to the desk via approve (that allowance IS depth); no fund().
    function _capAndOpen(BuyDesk desk, address owner_, uint256 usdtAmount, uint256 capGoat) internal {
        usdt.mint(owner_, usdtAmount);
        vm.prank(owner_);
        usdt.approve(address(desk), usdtAmount);
        vm.prank(owner_);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 1 days), capGoat);
    }

    // --- (a) createDesk bookkeeping: owner() and shared token/registry wiring ---

    function test_createDesk_sets_owner_and_shares_usdt_goat_registry() public {
        vm.prank(solo);
        address deskAddr = factory.createDesk("Solo Desk");
        BuyDesk desk = BuyDesk(deskAddr);
        assertEq(desk.owner(), solo);
        assertEq(address(desk.usdt()), address(usdt));
        assertEq(address(desk.goat()), address(goat));
        assertEq(address(desk.registry()), address(reg));
    }

    // --- (b) one desk per owner ---

    function test_createDesk_second_call_reverts_AlreadyHasDesk() public {
        vm.startPrank(solo);
        factory.createDesk("Solo Desk");
        vm.expectRevert(BuyDeskFactory.AlreadyHasDesk.selector);
        factory.createDesk("Solo Desk Take Two");
        vm.stopPrank();
    }

    // --- (c) DeskCreated event + desks/deskOf/desksLength bookkeeping ---

    function test_createDesk_emits_event_and_updates_bookkeeping() public {
        address predicted = vm.computeCreateAddress(address(factory), vm.getNonce(address(factory)));

        vm.expectEmit(true, true, false, true, address(factory));
        emit BuyDeskFactory.DeskCreated(solo, predicted, 0);
        vm.prank(solo);
        address deskAddr = factory.createDesk("Solo Desk");

        assertEq(deskAddr, predicted);
        assertEq(factory.desksLength(), 1);
        assertEq(factory.desks(0), predicted);
        assertEq(factory.deskOf(solo), predicted);
    }

    // --- (g) createDesk sets nameOf and emits DeskNamed ---

    function test_createDesk_sets_name_and_emits_DeskNamed() public {
        address predicted = vm.computeCreateAddress(address(factory), vm.getNonce(address(factory)));

        vm.expectEmit(true, true, false, true, address(factory));
        emit BuyDeskFactory.DeskNamed(solo, predicted, "Alice Desk");
        vm.prank(solo);
        address deskAddr = factory.createDesk("Alice Desk");

        assertEq(deskAddr, predicted);
        assertEq(factory.nameOf(solo), "Alice Desk");
    }

    // --- (h) setDeskName updates nameOf and emits DeskNamed ---

    function test_setDeskName_updates_name_and_emits_DeskNamed() public {
        vm.prank(solo);
        address deskAddr = factory.createDesk("Alice Desk");

        vm.expectEmit(true, true, false, true, address(factory));
        emit BuyDeskFactory.DeskNamed(solo, deskAddr, "Renamed");
        vm.prank(solo);
        factory.setDeskName("Renamed");

        assertEq(factory.nameOf(solo), "Renamed");
    }

    // --- (i) setDeskName from an address with no desk reverts NoDesk ---

    function test_setDeskName_reverts_NoDesk_when_caller_has_no_desk() public {
        vm.expectRevert(BuyDeskFactory.NoDesk.selector);
        vm.prank(solo);
        factory.setDeskName("Nope");
    }

    // --- (d) enrolled owner's desk accepts a sell ---

    function test_enrolled_owner_desk_accepts_sell() public {
        vm.prank(ownerA);
        address deskAddr = factory.createDesk("Owner A Desk");
        BuyDesk desk = BuyDesk(deskAddr);

        _capAndOpen(desk, ownerA, 10e6, 1000e18);

        vm.prank(minter);
        goat.mint(workerA, 1000e18);
        vm.prank(workerA);
        goat.approve(deskAddr, type(uint256).max);

        vm.prank(workerA);
        desk.sell(600e18);

        assertEq(usdt.balanceOf(workerA), 6e6); // 600 GOAT * 0.01 USDT/GOAT default bid
        assertEq(goat.balanceOf(ownerA), 600e18);
        assertEq(goat.balanceOf(workerA), 400e18);
    }

    // --- (e) non-enrolled owner's desk rejects sells until the safe enrolls them ---

    function test_nonenrolled_owner_desk_reverts_TransferRestricted_until_enrolled() public {
        vm.prank(ownerB);
        address deskAddr = factory.createDesk("Owner B Desk");
        BuyDesk desk = BuyDesk(deskAddr);

        _capAndOpen(desk, ownerB, 10e6, 1000e18);

        vm.prank(minter);
        goat.mint(workerB, 100e18);
        vm.prank(workerB);
        goat.approve(deskAddr, type(uint256).max);

        vm.expectRevert(GoatCoin.TransferRestricted.selector);
        vm.prank(workerB);
        desk.sell(1e18);

        // safe enrolls the pure donor -> sells now succeed
        vm.prank(safe);
        reg.setEnrolled(ownerB, true, bytes32(0));

        vm.prank(workerB);
        desk.sell(1e18);
        assertEq(goat.balanceOf(ownerB), 1e18);
    }

    // --- (f) two desks from two different owners coexist independently ---

    function test_two_desks_coexist_independently() public {
        vm.prank(ownerA);
        address deskAAddr = factory.createDesk("Owner A Desk");
        vm.prank(ownerB);
        address deskBAddr = factory.createDesk("Owner B Desk");

        assertTrue(deskAAddr != deskBAddr);

        BuyDesk deskA = BuyDesk(deskAAddr);
        BuyDesk deskB = BuyDesk(deskBAddr);

        vm.prank(ownerA);
        deskA.setBid(20_000);
        vm.prank(ownerB);
        deskB.setBid(30_000);

        assertEq(deskA.bid(), 20_000);
        assertEq(deskB.bid(), 30_000);
        assertEq(factory.desksLength(), 2);
        assertEq(factory.deskOf(ownerA), deskAAddr);
        assertEq(factory.deskOf(ownerB), deskBAddr);
    }
}
