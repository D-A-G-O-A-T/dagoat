// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {EpochSettlement} from "../src/EpochSettlement.sol";
import {FounderResolver} from "../src/FounderResolver.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";

/// Deploys the optimistic-settlement lane alongside the existing free-market stack.
/// A FRESH HoldbackEscrow (its own vault) — the existing one is bound to WorkMinter.
contract DeployEpochSettlement is Script {
    error ChainNotAllowed();
    error SettlementAddressMismatch();

    /// Canonical entrypoint — publishes to `./deployments/<chainid>.epoch.json`, the path
    /// `dev-up.ps1`, `testnet-up.ps1` and operators read. Production deploys use this.
    function run() external {
        _run(defaultManifestPath());
    }

    /// Publish to an explicit path instead of the canonical one.
    ///
    /// This exists for the tests, and it is load-bearing rather than cosmetic. `forge` runs the
    /// test functions of a contract in parallel, and BOTH tests in `DeployEpochSettlementTest`
    /// call the script and then read the manifest back to assert what it actually published —
    /// that round trip is the point of the assertion, so it is kept. With a single canonical
    /// path the two writers raced: `vm.writeJson` truncates before it writes, so one test could
    /// read the file mid-write and observe it empty. Measured at 1 failure in 10 full
    /// `forge test` runs before this split. Giving each test its own file removes the shared
    /// mutable state instead of retrying around it — a ~10% flaky gate is a gate nobody trusts,
    /// and `_readEpochManifest`'s own doc says why that is worse than a red one.
    function run(string memory manifestPath) external {
        _run(manifestPath);
    }

    function defaultManifestPath() public view returns (string memory) {
        return string.concat("./deployments/", vm.toString(block.chainid), ".epoch.json");
    }

    function _run(string memory manifestPath) internal {
        if (block.chainid != 84532 && block.chainid != 31337) revert ChainNotAllowed();
        address safe = vm.envAddress("SAFE_ADDRESS");
        address founder = vm.envAddress("FOUNDER_ADDRESS");
        address reserve = vm.envAddress("RESERVE_ADDRESS");
        address watcher = vm.envAddress("WATCHER_ADDRESS");
        GoatCoin goat = GoatCoin(vm.envAddress("GOAT_ADDRESS"));
        EnrollmentRegistry reg = EnrollmentRegistry(vm.envAddress("REGISTRY_ADDRESS"));

        uint256 rate = vm.envOr("RATE", uint256(1e18) / 24000);
        // Founder 2026-07-14: 67 GOAT/day time-based rate cap (GOAT wei).
        uint256 capPerDay = vm.envOr("CAP_PER_DAY", uint256(67e18));
        uint64 window = uint64(vm.envOr("CHALLENGE_WINDOW", uint256(12 hours)));
        uint256 pbond = vm.envOr("PROPOSER_BOND", uint256(0.01 ether));
        uint256 cbond = vm.envOr("CHALLENGER_BOND", uint256(0.01 ether));

        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);

        vm.startBroadcast(deployerPk);
        WorkerBinding binding = new WorkerBinding();
        HoldbackEscrow escrow = new HoldbackEscrow(safe, goat, reserve);
        // FounderResolver pins its settlement immutably and EpochSettlement now rejects a zero
        // resolver, so the pair is mutually dependent. The resolver belongs to this lane (like
        // binding/escrow) rather than to the operator's env, so the script keeps deploying it —
        // the cycle is broken by predicting the settlement's CREATE address instead of leaving
        // the resolver slot empty until a manual Safe call.
        address predictedSettlement = vm.computeCreateAddress(deployer, vm.getNonce(deployer) + 1);
        FounderResolver resolver = new FounderResolver(founder, predictedSettlement);
        EpochSettlement settle = new EpochSettlement(
            safe,
            goat,
            escrow,
            reg,
            binding,
            500,
            7 days,
            rate,
            capPerDay,
            window,
            pbond,
            cbond,
            address(resolver),
            watcher
        );
        if (address(settle) != predictedSettlement) revert SettlementAddressMismatch();
        vm.stopBroadcast();

        console.log("workerBinding:      ", address(binding));
        console.log("epochHoldbackEscrow:", address(escrow));
        console.log("epochSettlement:    ", address(settle));
        console.log("founderResolver:    ", address(resolver));
        console.log("resolver wired at construction - NO setResolver step required.");
        console.log("VERIFY FIRST (nonce race would mis-pin the resolver):");
        console.log("  cast call <founderResolver> 'settlement()(address)' == <epochSettlement>");
        console.log("NEXT (from SAFE):");
        console.log("  escrow.setVault(epochSettlement)");
        console.log("  goat.setMinter(epochSettlement, true)");
        console.log("  registry.setSystemAddress(epochSettlement, true)");
        console.log("  registry.setSystemAddress(epochHoldbackEscrow, true)");

        string memory k = "epoch";
        vm.serializeAddress(k, "workerBinding", address(binding));
        vm.serializeAddress(k, "epochHoldbackEscrow", address(escrow));
        vm.serializeAddress(k, "epochSettlement", address(settle));
        string memory j = vm.serializeAddress(k, "founderResolver", address(resolver));
        vm.writeJson(j, manifestPath);
    }
}
