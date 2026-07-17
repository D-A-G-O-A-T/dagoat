// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {JobVault} from "../src/JobVault.sol";
import {RedemptionDesk} from "../src/RedemptionDesk.sol";
import {MockUSDT} from "../test/mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// Season-0 testnet deployment. HARD GATE (spec §0): allows only Base
/// Sepolia (84532) and local anvil (31337) — real-money deployment is
/// blocked until the S6 counsel memo.
contract Deploy is Script {
    error ChainNotAllowed();

    function run() external {
        // Allowlist: Base Sepolia + local anvil ONLY. The counsel embargo
        // (spec §0) is code: no value-bearing chain can be a misconfig away.
        if (block.chainid != 84532 && block.chainid != 31337) revert ChainNotAllowed();

        address safe = vm.envAddress("SAFE_ADDRESS");
        address founder = vm.envAddress("FOUNDER_ADDRESS");
        address reserve = vm.envAddress("RESERVE_ADDRESS");

        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));

        MockUSDT usdt = new MockUSDT(); // testnet only
        EnrollmentRegistry reg = new EnrollmentRegistry(safe);
        GoatCoin goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        HoldbackEscrow escrow = new HoldbackEscrow(safe, goat, reserve);
        RedemptionDesk desk = new RedemptionDesk(safe, IERC20(address(usdt)), goat, reg, founder);
        JobVault vault = new JobVault(safe, IERC20(address(usdt)), goat, escrow, address(desk));

        vm.stopBroadcast();

        console.log("MockUSDT:          ", address(usdt));
        console.log("EnrollmentRegistry:", address(reg));
        console.log("GoatCoin:          ", address(goat));
        console.log("HoldbackEscrow:    ", address(escrow));
        console.log("RedemptionDesk:    ", address(desk));
        console.log("JobVault:          ", address(vault));
        console.log("");
        console.log("NEXT (from SAFE_ADDRESS):");
        console.log("  escrow.setVault(vault)");
        console.log("  goat.setMinter(vault, true)");
        console.log("  registry.setSystemAddress for: escrow, vault, desk, founder, reserve, safe");
    }
}
