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

    function run() external {
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

        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        WorkerBinding binding = new WorkerBinding();
        HoldbackEscrow escrow = new HoldbackEscrow(safe, goat, reserve);
        EpochSettlement settle = new EpochSettlement(
            safe, goat, escrow, reg, binding, 500, 7 days, rate, capPerDay, window, pbond, cbond, address(0), watcher
        );
        FounderResolver resolver = new FounderResolver(founder, address(settle));
        vm.stopBroadcast();

        console.log("workerBinding:      ", address(binding));
        console.log("epochHoldbackEscrow:", address(escrow));
        console.log("epochSettlement:    ", address(settle));
        console.log("founderResolver:    ", address(resolver));
        console.log("NEXT (from SAFE):");
        console.log("  escrow.setVault(epochSettlement)");
        console.log("  goat.setMinter(epochSettlement, true)");
        console.log("  registry.setSystemAddress(epochSettlement, true)");
        console.log("  registry.setSystemAddress(epochHoldbackEscrow, true)");
        console.log("  settlement.setResolver(founderResolver)");

        string memory k = "epoch";
        vm.serializeAddress(k, "workerBinding", address(binding));
        vm.serializeAddress(k, "epochHoldbackEscrow", address(escrow));
        vm.serializeAddress(k, "epochSettlement", address(settle));
        string memory j = vm.serializeAddress(k, "founderResolver", address(resolver));
        vm.writeJson(j, string.concat("./deployments/", vm.toString(block.chainid), ".epoch.json"));
    }
}
