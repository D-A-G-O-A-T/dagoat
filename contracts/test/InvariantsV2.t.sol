// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {WorkMinter} from "../src/WorkMinter.sol";
import {BuyDesk} from "../src/BuyDesk.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// Invariant fuzz suite for the free-market mint system (WorkMinter +
/// BuyDesk + HoldbackEscrow).
///
/// BuyDesk is now the allowance (wallet-direct) model: the desk never
/// custodies USDT. It pays sellers from the owner's own wallet via
/// allowance, so it can only ever pay out the owner's real USDT (No-Ponzi),
/// and its own USDT balance is always 0. Season-0 free-market mint law is
/// that GOAT supply is never backed by or pegged to USDT; that is the v1
/// JobVault/RedemptionDesk model, retired for v2.
contract Handler is Test {
    EnrollmentRegistry public reg;
    GoatCoin public goat;
    HoldbackEscrow public escrow;
    WorkMinter public minter;
    BuyDesk public desk;
    MockUSDT public usdt;
    address public safe;
    address public founder;

    address[] public workers;
    bytes32[] public jobIds;
    uint256 public jobCounter;
    // WorkMinter now rejects a replayed manifestRoot (S9 fix a), so each
    // handler mint must derive a fresh root — a constant root would make
    // every mint after the first revert.
    uint256 public mintNonce;

    uint256 public totalMintedGoat;
    uint256 public totalHoldbackCredited;
    uint256 public totalLiquidMinted;
    uint256 public totalHoldbackReleased;
    /// Always 0 — no slash action in this handler.
    uint256 public totalSlashed;

    /// Real USDT the owner has ever minted into their own wallet (funding
    /// in). The desk can never pay out more than this (No-Ponzi).
    uint256 public totalOwnerUsdtMinted;
    uint256 public totalUsdtPaidOut;
    uint256 public totalPaidBySaleMath;

    constructor(
        EnrollmentRegistry reg_,
        GoatCoin goat_,
        HoldbackEscrow escrow_,
        WorkMinter minter_,
        BuyDesk desk_,
        MockUSDT usdt_,
        address safe_,
        address founder_
    ) {
        reg = reg_;
        goat = goat_;
        escrow = escrow_;
        minter = minter_;
        desk = desk_;
        usdt = usdt_;
        safe = safe_;
        founder = founder_;
        for (uint256 i = 0; i < 5; i++) {
            address w = makeAddr(string(abi.encodePacked("worker", i)));
            workers.push(w);
            vm.prank(safe);
            reg.setEnrolled(w, true, bytes32(0));
            vm.prank(w);
            goat.approve(address(desk), type(uint256).max);
        }
    }

    function createJob(uint256 seed) external {
        seed; // silence unused; seed unused — create is unconditional when under cap
        if (jobIds.length >= 3) return;
        bytes32 id = keccak256(abi.encodePacked("jobv2", jobCounter++));
        jobIds.push(id);
        vm.prank(safe);
        minter.createJob(id, keccak256("catalog"), 1e18, 1500, address(0), true);
    }

    function mintBatch(uint256 jobSeed, uint8 workerCountSeed, uint64 unitsSeed) external {
        if (jobIds.length == 0) return;
        bytes32 id = jobIds[jobSeed % jobIds.length];
        (,,,,,, bool closed,) = minter.jobs(id);
        if (closed) return;
        if (escrow.jobReleased(id)) return;

        uint256 n = bound(uint256(workerCountSeed), 1, workers.length);
        address[] memory ws = new address[](n);
        uint256[] memory units = new uint256[](n);

        uint256 totalGoat;
        uint256 totalHb;
        uint256 totalLiquid;
        for (uint256 i = 0; i < n; i++) {
            ws[i] = workers[i];
            units[i] = bound(uint256(keccak256(abi.encode(unitsSeed, i))), 1, 5);
            uint256 goatAmount = units[i] * 1e18;
            uint256 hb = goatAmount * 1500 / 10_000;
            totalGoat += goatAmount;
            totalHb += hb;
            totalLiquid += goatAmount - hb;
        }

        vm.prank(safe);
        minter.mintBatch(id, keccak256(abi.encodePacked("manifest", mintNonce++)), ws, units);

        totalMintedGoat += totalGoat;
        totalHoldbackCredited += totalHb;
        totalLiquidMinted += totalLiquid;
    }

    function releaseEscrow(uint256 jobSeed) external {
        if (jobIds.length == 0) return;
        bytes32 id = jobIds[jobSeed % jobIds.length];
        if (escrow.jobReleased(id)) return;

        uint256 held;
        for (uint256 i = 0; i < workers.length; i++) {
            held += escrow.holdbackOf(id, workers[i]);
        }
        if (held == 0) return;

        vm.prank(safe);
        escrow.release(id);
        totalHoldbackReleased += held;
    }

    /// Owner tops up their own wallet with real USDT (funding in). The USDT
    /// stays in the wallet — the desk never holds it.
    function mintOwnerUsdt(uint96 amountSeed) external {
        uint256 amount = bound(uint256(amountSeed), 1, 100_000e6);
        usdt.mint(founder, amount);
        totalOwnerUsdtMinted += amount;
    }

    /// Owner commits (or lowers/clears) the desk cap == the allowance the
    /// desk may spend from the owner's wallet. approve(desk, 0) closes it.
    function setCap(uint96 capSeed) external {
        uint256 cap = bound(uint256(capSeed), 0, 200_000e6);
        vm.prank(founder);
        usdt.approve(address(desk), cap);
    }

    function setBid(uint256 newBidSeed) external {
        uint256 newBid = bound(newBidSeed, 0, 50_000);
        vm.prank(founder);
        desk.setBid(newBid);
    }

    function openSession(uint64 seed) external {
        seed; // silence unused
        vm.prank(founder);
        desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 7 days), type(uint256).max);
    }

    function sell(uint256 workerSeed, uint96 amountSeed) external {
        address w = workers[workerSeed % workers.length];
        uint256 bal = goat.balanceOf(w);
        if (bal == 0) return;

        (uint256 id,,,) = desk.currentSession();
        if (id == 0) {
            vm.prank(founder);
            desk.openSession(uint64(block.timestamp), uint64(block.timestamp + 7 days), type(uint256).max);
        }

        uint256 amount = bound(uint256(amountSeed), 1, bal);
        uint256 bidNow = desk.bid();
        uint256 expected = amount * bidNow / 1e18;
        if (expected == 0) return;
        // Allowance-model guards: the committed cap (allowance == depth) and
        // the owner's live wallet balance must both cover the payout.
        if (expected > desk.depth()) return;
        if (expected > usdt.balanceOf(founder)) return;

        uint256 sellerBefore = usdt.balanceOf(w);
        vm.prank(w);
        desk.sell(amount);
        uint256 actual = usdt.balanceOf(w) - sellerBefore;
        assertEq(actual, expected);
        totalUsdtPaidOut += actual;
        totalPaidBySaleMath += expected;
    }
}

contract InvariantsV2Test is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    WorkMinter minter;
    BuyDesk desk;
    MockUSDT usdt;
    Handler handler;
    address safe = makeAddr("safe");
    address founder = makeAddr("founder");
    address reserve = makeAddr("reserve");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        minter = new WorkMinter(safe, goat, escrow);
        usdt = new MockUSDT();
        desk = new BuyDesk(founder, IERC20(address(usdt)), goat, reg);

        vm.startPrank(safe);
        escrow.setVault(address(minter));
        goat.setMinter(address(minter), true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(address(minter), true);
        reg.setSystemAddress(address(desk), true);
        reg.setSystemAddress(founder, true);
        reg.setSystemAddress(reserve, true);
        reg.setSystemAddress(safe, true);
        vm.stopPrank();

        handler = new Handler(reg, goat, escrow, minter, desk, usdt, safe, founder);
        targetContract(address(handler));
    }

    function invariant_supply_conservation() public view {
        assertEq(goat.totalSupply(), handler.totalMintedGoat());
    }

    function invariant_holdback_conservation() public view {
        uint256 liveHeld;
        for (uint256 i = 0; i < 3; i++) {
            // handler caps jobs at 3
            if (i >= handler.jobCounter()) break;
            bytes32 id = keccak256(abi.encodePacked("jobv2", i));
            for (uint256 j = 0; j < 5; j++) {
                liveHeld += escrow.holdbackOf(id, handler.workers(j));
            }
        }
        assertEq(liveHeld + handler.totalHoldbackReleased() + handler.totalSlashed(), handler.totalHoldbackCredited());
        assertEq(handler.totalLiquidMinted() + handler.totalHoldbackCredited(), handler.totalMintedGoat());
    }

    /// Allowance model: the desk is a pure conduit and never custodies USDT
    /// (spec §7 invariant — its own USDT balance is always 0).
    function invariant_desk_never_custodies_usdt() public view {
        assertEq(usdt.balanceOf(address(desk)), 0);
    }

    /// No-Ponzi: total USDT paid to sellers never exceeds the owner's real
    /// USDT ever provided, and every payout equals the posted-bid sale math.
    function invariant_noponzi_payout_bounded() public view {
        assertLe(handler.totalUsdtPaidOut(), handler.totalOwnerUsdtMinted());
        assertEq(handler.totalUsdtPaidOut(), handler.totalPaidBySaleMath());
    }

    /// Owner wallet accounting: the founder's USDT only ever leaves via
    /// sells, so the live wallet balance is exactly funding-in minus paid-out.
    function invariant_owner_wallet_accounting() public view {
        assertEq(usdt.balanceOf(founder), handler.totalOwnerUsdtMinted() - handler.totalUsdtPaidOut());
    }

    function invariant_allowlist_integrity() public view {
        for (uint256 i = 0; i < 5; i++) {
            address w = handler.workers(i);
            if (goat.balanceOf(w) > 0) {
                assertTrue(reg.enrolled(w) || reg.systemAddress(w));
            }
        }
    }
}
