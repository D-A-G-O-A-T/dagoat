// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {BuyDeskFactory} from "../src/BuyDeskFactory.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// Deploys BuyDeskFactory (design 2026-07-13) on top of the existing
/// free-market stack. HARD GATE: allows only Base Sepolia (84532) and
/// local anvil (31337), mirroring DeployFreeMarket. Reads the already
/// deployed GOAT/registry/USDT addresses — the factory never deploys its
/// own token/registry, it only wires per-owner BuyDesk instances against
/// the existing ones.
contract DeployBuyDeskFactory is Script {
    error ChainNotAllowed();

    function run() external {
        if (block.chainid != 84532 && block.chainid != 31337) revert ChainNotAllowed();

        address goatAddress = vm.envAddress("GOAT_ADDRESS");
        address registryAddress = vm.envAddress("REGISTRY_ADDRESS");
        address usdtAddress = vm.envAddress("USDT_ADDRESS");

        GoatCoin goat = GoatCoin(goatAddress);
        EnrollmentRegistry reg = EnrollmentRegistry(registryAddress);
        IERC20 usdt = IERC20(usdtAddress);

        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));
        BuyDeskFactory factory = new BuyDeskFactory(usdt, goat, reg);
        vm.stopBroadcast();

        console.log("BuyDeskFactory:     ", address(factory));
        console.log("  usdt:             ", address(usdt));
        console.log("  goat:             ", address(goat));
        console.log("  registry:         ", address(reg));
        console.log("NEXT:");
        console.log("  factory.createDesk() from any enrolled wallet -> becomes a donor desk");

        string memory objKey = "factory";
        vm.serializeUint(objKey, "chainId", block.chainid);
        vm.serializeAddress(objKey, "goatCoin", address(goat));
        vm.serializeAddress(objKey, "enrollmentRegistry", address(reg));
        vm.serializeAddress(objKey, "mockUSDT", address(usdt));
        string memory finalJson = vm.serializeAddress(objKey, "buyDeskFactory", address(factory));
        vm.writeJson(finalJson, string.concat("./deployments/", vm.toString(block.chainid), ".factory.json"));
    }
}
