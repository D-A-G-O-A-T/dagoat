// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {EpochSettlement} from "../src/EpochSettlement.sol";
import {FounderResolver} from "../src/FounderResolver.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";
import {DeployEpochSettlement} from "../script/DeployEpochSettlement.s.sol";

/// Deploy-script smoke test: runs DeployEpochSettlement in-process against a
/// pre-existing GoatCoin/EnrollmentRegistry (as DeployFreeMarket would have left
/// them), performs the SAFE wiring calls the script prints as NEXT steps, then
/// drives one full optimistic-settlement cycle (propose -> confirm -> finalize ->
/// claim) against a real 2-leaf Merkle root and a real enrolled worker.
contract DeployEpochSettlementTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;

    address safe = makeAddr("safe");
    address founder = makeAddr("founder");
    address reserve = makeAddr("reserve");
    address watcher = makeAddr("watcher");
    address worker = makeAddr("worker");
    address other = makeAddr("other");
    address proposer = makeAddr("proposer");

    uint256 constant DEPLOYER_PK = 0xA11CE;

    function setUp() public {
        // Simulate the pre-existing free-market stack DeployFreeMarket would
        // have produced; DeployEpochSettlement is expected to reuse it via env.
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);

        vm.setEnv("SAFE_ADDRESS", vm.toString(safe));
        vm.setEnv("FOUNDER_ADDRESS", vm.toString(founder));
        vm.setEnv("RESERVE_ADDRESS", vm.toString(reserve));
        vm.setEnv("WATCHER_ADDRESS", vm.toString(watcher));
        vm.setEnv("GOAT_ADDRESS", vm.toString(address(goat)));
        vm.setEnv("REGISTRY_ADDRESS", vm.toString(address(reg)));
        vm.setEnv("DEPLOYER_PRIVATE_KEY", vm.toString(DEPLOYER_PK));

        vm.deal(proposer, 1 ether);
    }

    // Copied from EpochSettlement.t.sol (DRY across test files is not required by forge).
    function _leaf(address w, uint256 s) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(w, s))));
    }

    function _root2(bytes32 l0, bytes32 l1) internal pure returns (bytes32) {
        return l0 < l1 ? keccak256(abi.encode(l0, l1)) : keccak256(abi.encode(l1, l0));
    }

    function test_deployWireAndSettleEndToEnd() public {
        DeployEpochSettlement script = new DeployEpochSettlement();
        script.run();

        string memory path = string.concat("./deployments/", vm.toString(block.chainid), ".epoch.json");
        string memory json = vm.readFile(path);
        address escrowAddr = vm.parseJsonAddress(json, ".epochHoldbackEscrow");
        address settleAddr = vm.parseJsonAddress(json, ".epochSettlement");
        address resolverAddr = vm.parseJsonAddress(json, ".founderResolver");
        address bindingAddr = vm.parseJsonAddress(json, ".workerBinding");

        HoldbackEscrow escrow = HoldbackEscrow(escrowAddr);
        EpochSettlement settle = EpochSettlement(settleAddr);
        FounderResolver resolver = FounderResolver(resolverAddr);
        WorkerBinding binding = WorkerBinding(bindingAddr);

        // Sanity: freshly deployed, unwired.
        assertEq(address(escrow.goat()), address(goat));
        assertEq(escrow.vault(), address(0));
        assertEq(settle.watcher(), watcher);
        assertEq(settle.resolver(), address(0));
        assertEq(resolver.founder(), founder);
        assertEq(resolver.settlement(), address(settle));
        assertEq(address(settle.binding()), bindingAddr);

        // Wire exactly the NEXT calls the script prints, as SAFE would via cast.
        vm.startPrank(safe);
        escrow.setVault(address(settle));
        goat.setMinter(address(settle), true);
        reg.setSystemAddress(address(settle), true);
        reg.setSystemAddress(address(escrow), true);
        settle.setResolver(address(resolver));
        reg.setEnrolled(worker, true, bytes32(0));
        vm.stopPrank();
        vm.prank(worker);
        binding.bind("GOAT-worker");

        assertEq(escrow.vault(), address(settle));
        assertTrue(goat.isMinter(address(settle)));
        assertEq(settle.resolver(), address(resolver));

        // Baseline batch at score 0, then earn batch — first claim mints 0.
        uint256 workerScore = 1_000_000;
        uint256 otherScore = 1;
        bytes32[] memory empty = new bytes32[](0);
        {
            bytes32 root0 = _leaf(worker, 0);
            uint256 pbond0 = settle.proposerBond();
            vm.prank(proposer);
            settle.proposeBatch{value: pbond0}(1, root0, bytes32(0));
            vm.warp(block.timestamp + settle.challengeWindow() + 1);
            vm.prank(watcher);
            settle.confirmEpoch(1);
            settle.finalizeBatch(1);
            settle.claimPayout(1, worker, 0, empty);
            assertTrue(settle.hasBaseline(worker));
            assertEq(goat.balanceOf(worker), 0);
        }

        // Real 2-leaf Merkle tree for (worker, workerScore) and (other, otherScore).
        bytes32 lw = _leaf(worker, workerScore);
        bytes32 lo = _leaf(other, otherScore);
        bytes32 root = _root2(lw, lo);

        uint256 pbond = settle.proposerBond();
        vm.prank(proposer);
        settle.proposeBatch{value: pbond}(2, root, bytes32(0));

        vm.warp(block.timestamp + settle.challengeWindow() + 1);
        vm.prank(watcher);
        settle.confirmEpoch(2);
        settle.finalizeBatch(2);

        vm.warp(uint256(settle.lastClaimTime(worker)) + 1 days);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = lo;
        settle.claimPayout(2, worker, workerScore, proof);

        uint256 expectGross = workerScore * settle.rate();
        uint256 expectHb = expectGross * settle.holdbackBps() / 10_000;
        uint256 expectLiquid = expectGross - expectHb;
        assertGt(expectLiquid, 0);
        assertEq(goat.balanceOf(worker), expectLiquid);
        assertEq(escrow.holdbackOf(bytes32(uint256(2)), worker), expectHb);
        assertEq(settle.lastClaimedCumulative(worker), workerScore);
    }
}
