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
    address challenger = makeAddr("challenger");

    uint256 constant DEPLOYER_PK = 0xA11CE;

    event DisputeSeen(uint256 indexed epoch, address proposer, address challenger);

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
        vm.deal(challenger, 1 ether);
    }

    // Copied from EpochSettlement.t.sol (DRY across test files is not required by forge).
    function _leaf(address w, uint256 s) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(w, s))));
    }

    function _root2(bytes32 l0, bytes32 l1) internal pure returns (bytes32) {
        return l0 < l1 ? keccak256(abi.encode(l0, l1)) : keccak256(abi.encode(l1, l0));
    }

    /// CRITICAL 4: proposeBatch is permissionless from the block the settlement is mined, so
    /// the fraud-challenge path must already work BEFORE any manual Safe call. This test does
    /// zero SAFE wiring: it deploys, proposes a fraudulent root, challenges it, and has the
    /// founder rule for the challenger — the whole path that a zero resolver would disable.
    /// Mutation: pass address(0) for resolver_ in DeployEpochSettlement.s.sol.
    function test_deploy_fraudChallengePathLiveBeforeAnySafeWiring() public {
        DeployEpochSettlement script = new DeployEpochSettlement();
        string memory manifest = _testManifestPath("fraudpath");
        script.run(manifest);

        string memory json = _readEpochManifest(manifest);
        EpochSettlement settle = EpochSettlement(vm.parseJsonAddress(json, ".epochSettlement"));
        FounderResolver resolver = FounderResolver(vm.parseJsonAddress(json, ".founderResolver"));

        assertTrue(settle.resolver() != address(0), "settlement deployed with no resolver");
        assertEq(settle.resolver(), address(resolver));
        assertEq(resolver.settlement(), address(settle));

        // Bonds read into locals first: an external read inside the {value:} expression would
        // consume the vm.prank below and the batch would be attributed to this test contract.
        uint256 pbond = settle.proposerBond();
        uint256 cbond = settle.challengerBond();

        // NOTE: not a single vm.prank(safe) below — the lane is unwired apart from the resolver.
        vm.prank(proposer);
        settle.proposeBatch{value: pbond}(1, keccak256("fraudulent-root"), bytes32(0));

        vm.expectEmit(true, false, false, true, address(resolver));
        emit DisputeSeen(1, proposer, challenger);
        vm.prank(challenger);
        settle.challengeBatch{value: cbond}(1, keccak256("counter-evidence"));

        vm.prank(founder);
        resolver.decide(1, false, keccak256("fraud"));

        (,,,,,,,,, EpochSettlement.Status st) = settle.batches(1);
        assertTrue(st == EpochSettlement.Status.ChallengerWon, "fraudulent batch was not overturned");
    }

    function test_deployWireAndSettleEndToEnd() public {
        DeployEpochSettlement script = new DeployEpochSettlement();
        string memory manifest = _testManifestPath("endtoend");
        script.run(manifest);

        string memory json = _readEpochManifest(manifest);
        address escrowAddr = vm.parseJsonAddress(json, ".epochHoldbackEscrow");
        address settleAddr = vm.parseJsonAddress(json, ".epochSettlement");
        address resolverAddr = vm.parseJsonAddress(json, ".founderResolver");
        address bindingAddr = vm.parseJsonAddress(json, ".workerBinding");

        HoldbackEscrow escrow = HoldbackEscrow(escrowAddr);
        EpochSettlement settle = EpochSettlement(settleAddr);
        FounderResolver resolver = FounderResolver(resolverAddr);
        WorkerBinding binding = WorkerBinding(bindingAddr);

        // Sanity: freshly deployed, unwired EXCEPT the resolver, which must be live from
        // block one — proposeBatch is permissionless, so a zero resolver would leave the
        // fraud-challenge path inoperative until a manual Safe call (CRITICAL 4).
        assertEq(address(escrow.goat()), address(goat));
        assertEq(escrow.vault(), address(0));
        assertEq(settle.watcher(), watcher);
        assertTrue(settle.resolver() != address(0), "settlement deployed with no resolver");
        assertEq(settle.resolver(), resolverAddr);
        assertEq(resolver.founder(), founder);
        assertEq(resolver.settlement(), address(settle));
        assertEq(address(settle.binding()), bindingAddr);

        // Wire exactly the NEXT calls the script prints, as SAFE would via cast.
        // setResolver is deliberately absent: the script no longer lists it.
        vm.startPrank(safe);
        escrow.setVault(address(settle));
        goat.setMinter(address(settle), true);
        reg.setSystemAddress(address(settle), true);
        reg.setSystemAddress(address(escrow), true);
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
        // Per-(epoch, worker) holdback jobId (EpochSettlement._holdbackJobId), re-derived
        // here rather than read back from the contract so this test pins the convention.
        assertEq(escrow.holdbackOf(keccak256(abi.encode(uint256(2), worker)), worker), expectHb);
        assertEq(settle.lastClaimedCumulative(worker), workerScore);
    }

    /// Per-test manifest path, so the two tests in this contract never write the same file.
    ///
    /// `forge` runs a contract's test functions in parallel, and both tests here publish and
    /// then read back. While both used the canonical `./deployments/<chainid>.epoch.json`,
    /// they raced — `vm.writeJson` truncates before it writes, so one test could read the
    /// other's file mid-write and see it empty. That was 1 failure in 10 full `forge test`
    /// runs. The fix is separate files (`DeployEpochSettlement.run(string)`), not a retry:
    /// see that overload's doc. Keeping the round trip matters — it is what proves the script
    /// actually publishes — so only the sharing was removed.
    ///
    /// These files are gitignored (`contracts/deployments/*.epoch.t-*.json`) and are
    /// deliberately NOT the canonical path, so a test run can no longer truncate the tracked
    /// manifest that `dev-up.ps1` and operators read.
    function _testManifestPath(string memory suffix) internal view returns (string memory) {
        return string.concat("./deployments/", vm.toString(block.chainid), ".epoch.t-", suffix, ".json");
    }

    /// Read a manifest the script just wrote, failing with a message that names the file and
    /// the likely cause rather than a bare parser error.
    ///
    /// The guard stays even though the in-suite race is gone: the file can still be absent or
    /// truncated if the script did not reach its `vm.writeJson`, and `vm.parseJsonAddress`
    /// reports that as `EOF while parsing a value at line 1 column 0`, which names neither the
    /// file nor the cause and reads exactly like a flaky test. A phantom flake attached to a
    /// suite is worse than a red one: it becomes a standing licence to dismiss the signal the
    /// gate exists to produce.
    function _readEpochManifest(string memory path) internal view returns (string memory) {
        string memory json = vm.readFile(path);
        require(
            bytes(json).length > 0,
            string.concat(
                "epoch deployment manifest is EMPTY at ",
                path,
                " -- script.run() did not publish it, or another process truncated it. ",
                "This is stale filesystem state, not a contract defect: re-run `forge test`."
            )
        );
        return json;
    }
}
