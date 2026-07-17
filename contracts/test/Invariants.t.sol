// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {JobVault} from "../src/JobVault.sol";
import {RedemptionDesk} from "../src/RedemptionDesk.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// Random valid ops against the full wired system.
contract Handler is Test {
    EnrollmentRegistry public reg;
    GoatCoin public goat;
    HoldbackEscrow public escrow;
    JobVault public vault;
    RedemptionDesk public desk;
    MockUSDT public usdt;
    address public safe;
    address public founder;

    address[] public workers;
    bytes32[] public jobIds;
    uint256 public jobCounter;
    uint256 public totalMinted;

    constructor(
        EnrollmentRegistry reg_,
        GoatCoin goat_,
        HoldbackEscrow escrow_,
        JobVault vault_,
        RedemptionDesk desk_,
        MockUSDT usdt_,
        address safe_,
        address founder_
    ) {
        reg = reg_;
        goat = goat_;
        escrow = escrow_;
        vault = vault_;
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

    function createJob(uint96 budget) external {
        uint256 b = bound(uint256(budget), 1e6, 1_000e6);
        usdt.mint(founder, b);
        vm.prank(founder);
        usdt.approve(address(vault), b);
        bytes32 id = keccak256(abi.encodePacked("job", jobCounter++));
        jobIds.push(id);
        vm.prank(safe);
        vault.createJob(id, keccak256("catalog"), founder, b, 1500, address(0), true);
    }

    function mintBatch(uint256 jobSeed, uint96 amountSeed) external {
        if (jobIds.length == 0) return;
        bytes32 id = jobIds[jobSeed % jobIds.length];
        (,, uint256 budget, uint256 minted,,,, bool closed,) = vault.jobs(id);
        if (closed) return;
        uint256 headroomUsdt = budget - vault.usdtValueCeil(minted);
        if (headroomUsdt == 0) return;
        uint256 maxGoat = headroomUsdt * 1e18 / vault.RATE();
        uint256 amount = bound(uint256(amountSeed), 1e18, maxGoat < 1e18 ? 1e18 : maxGoat);
        if (vault.usdtValueCeil(minted + amount) > budget) return;
        address[] memory ws = new address[](1);
        uint256[] memory as_ = new uint256[](1);
        ws[0] = workers[jobSeed % workers.length];
        as_[0] = amount;
        vm.prank(safe);
        vault.mintBatch(id, keccak256("manifest"), ws, as_);
        totalMinted += amount;
    }

    function releaseJob(uint256 jobSeed) external {
        if (jobIds.length == 0) return;
        bytes32 id = jobIds[jobSeed % jobIds.length];
        if (escrow.jobReleased(id)) return;
        vm.prank(safe);
        escrow.release(id);
    }

    function closeJob(uint256 jobSeed) external {
        if (jobIds.length == 0) return;
        bytes32 id = jobIds[jobSeed % jobIds.length];
        (,,, uint256 minted,,,, bool closed,) = vault.jobs(id);
        if (closed) return;
        if (minted > 0 && !escrow.jobReleased(id)) {
            vm.prank(safe);
            escrow.release(id);
        }
        vm.prank(safe);
        vault.closeJob(id);
    }

    function redeemSome(uint256 workerSeed, uint96 amountSeed) external {
        address w = workers[workerSeed % workers.length];
        uint256 bal = goat.balanceOf(w);
        if (bal < 1e18) return;
        (uint256 id,,,) = desk.currentWindow();
        if (id == 0) {
            vm.prank(safe);
            desk.openWindow(uint64(block.timestamp), uint64(block.timestamp + 7 days), type(uint256).max);
        }
        uint256 amount = bound(uint256(amountSeed), 1e18, bal);
        vm.prank(w);
        desk.redeem(amount);
    }
}

contract InvariantsTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    JobVault vault;
    RedemptionDesk desk;
    MockUSDT usdt;
    Handler handler;
    address safe = makeAddr("safe");
    address founder = makeAddr("founder");
    address reserve = makeAddr("reserve");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        usdt = new MockUSDT();
        desk = new RedemptionDesk(safe, IERC20(address(usdt)), goat, reg, founder);
        vault = new JobVault(safe, IERC20(address(usdt)), goat, escrow, address(desk));
        vm.startPrank(safe);
        escrow.setVault(address(vault));
        goat.setMinter(address(vault), true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(address(vault), true);
        reg.setSystemAddress(address(desk), true);
        reg.setSystemAddress(founder, true);
        reg.setSystemAddress(reserve, true);
        vm.stopPrank();
        handler = new Handler(reg, goat, escrow, vault, desk, usdt, safe, founder);
        targetContract(address(handler));
    }

    /// Invariant 2 (spec §5): the desk can always buy back every GOAT
    /// held outside the beneficiary/reserve at the published rate.
    /// Assumes beneficiary/reserve never recirculate GOAT (policy + the
    /// desk's BeneficiaryCannotRedeem guard); the handler never re-transfers
    /// from founder, matching that assumption.
    function invariant_desk_solvency() public view {
        uint256 outstanding = goat.totalSupply() - goat.balanceOf(founder) - goat.balanceOf(reserve);
        assertGe(usdt.balanceOf(address(desk)), outstanding * desk.RATE() / 1e18);
    }

    /// Invariant 1 (spec §5): no job ever mints beyond its escrow.
    function invariant_mint_never_exceeds_escrow() public view {
        for (uint256 i = 0; i < handler.jobCounter(); i++) {
            bytes32 id = keccak256(abi.encodePacked("job", i));
            (,, uint256 budget, uint256 minted,,,,,) = vault.jobs(id);
            assertLe(vault.usdtValue(minted), budget);
        }
    }

    /// Invariant 3 (spec §5): GOAT supply is conserved — everything the
    /// vault ever minted is still held by someone; no hidden sink exists.
    function invariant_supply_conservation() public view {
        assertEq(goat.totalSupply(), handler.totalMinted());
    }

    /// The vault always holds enough USDT to refund every open job.
    function invariant_vault_covers_open_budgets() public view {
        uint256 owed;
        for (uint256 i = 0; i < handler.jobCounter(); i++) {
            bytes32 id = keccak256(abi.encodePacked("job", i));
            (,, uint256 budget,,,,, bool closed,) = vault.jobs(id);
            if (!closed) owed += budget - vault.usdtFunded(id);
        }
        assertGe(usdt.balanceOf(address(vault)), owed);
    }
}
