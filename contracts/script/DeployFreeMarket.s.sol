// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {WorkMinter} from "../src/WorkMinter.sol";
import {BuyDesk} from "../src/BuyDesk.sol";
import {MockUSDT} from "../test/mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// Free-market mint system deployment (WorkMinter + BuyDesk + HoldbackEscrow).
/// HARD GATE: allows only Base Sepolia (84532) and local anvil (31337).
/// Writes a JSON deployment manifest under ./deployments/<chainId>.json
/// for frontend consumption.
contract DeployFreeMarket is Script {
    error ChainNotAllowed();
    error PartialExistingSet();

    function run() external {
        // Allowlist: Base Sepolia + local anvil ONLY.
        if (block.chainid != 84532 && block.chainid != 31337) revert ChainNotAllowed();

        address safe = vm.envAddress("SAFE_ADDRESS");
        address founder = vm.envAddress("FOUNDER_ADDRESS");
        address reserve = vm.envAddress("RESERVE_ADDRESS");

        address existingGoat = vm.envOr("EXISTING_GOAT", address(0));
        address existingRegistry = vm.envOr("EXISTING_REGISTRY", address(0));
        address existingUsdt = vm.envOr("EXISTING_USDT", address(0));
        bool anySet = existingGoat != address(0) || existingRegistry != address(0) || existingUsdt != address(0);
        bool allSet = existingGoat != address(0) && existingRegistry != address(0) && existingUsdt != address(0);
        if (anySet && !allSet) revert PartialExistingSet();

        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));

        MockUSDT usdt;
        EnrollmentRegistry reg;
        GoatCoin goat;
        if (allSet) {
            usdt = MockUSDT(existingUsdt);
            reg = EnrollmentRegistry(existingRegistry);
            goat = GoatCoin(existingGoat);
        } else {
            usdt = new MockUSDT();
            reg = new EnrollmentRegistry(safe);
            goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        }

        HoldbackEscrow escrow = new HoldbackEscrow(safe, goat, reserve);
        WorkMinter minter = new WorkMinter(safe, goat, escrow);
        BuyDesk desk = new BuyDesk(founder, IERC20(address(usdt)), goat, reg);

        vm.stopBroadcast();

        console.log("MockUSDT:          ", address(usdt));
        console.log("EnrollmentRegistry:", address(reg));
        console.log("GoatCoin:          ", address(goat));
        console.log("HoldbackEscrow:    ", address(escrow));
        console.log("WorkMinter:        ", address(minter));
        console.log("BuyDesk:           ", address(desk));
        console.log("");
        console.log("NEXT (from SAFE_ADDRESS):");
        console.log("  escrow.setVault(workMinter)");
        console.log("  goat.setMinter(workMinter, true)");
        console.log("  registry.setSystemAddress for: escrow, workMinter, buyDesk, founder, reserve, safe");

        string memory objKey = "deployment";
        vm.serializeUint(objKey, "chainId", block.chainid);
        vm.serializeAddress(objKey, "mockUSDT", address(usdt));
        vm.serializeAddress(objKey, "enrollmentRegistry", address(reg));
        vm.serializeAddress(objKey, "goatCoin", address(goat));
        vm.serializeAddress(objKey, "holdbackEscrow", address(escrow));
        vm.serializeAddress(objKey, "workMinter", address(minter));
        vm.serializeAddress(objKey, "buyDesk", address(desk));
        vm.serializeString(objKey, "unitReward", "1000000000000000000");
        string memory finalJson = vm.serializeString(objKey, "bid", "10000");
        vm.writeJson(finalJson, string.concat("./deployments/", vm.toString(block.chainid), ".json"));
    }
}
