// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {SponsoredBuyDesk} from "../src/SponsoredBuyDesk.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";

/// Append-only Stream G publish/bind/activate helper for already-deployed addresses.
/// G1 only supports chain 31337.
contract PublishStreamG is Script {
    error ChainNotAllowed();
    error BaseSepoliaPhaseGated();
    error ZeroAddress();

    function run() external {
        if (block.chainid == 84532) revert BaseSepoliaPhaseGated();
        if (block.chainid != 31337) revert ChainNotAllowed();

        address feeRegistry = vm.envAddress("STREAM_G_FEE_TOKEN_REGISTRY");
        address sidecar = vm.envAddress("STREAM_G_WALLET_SPONSORSHIP_REGISTRY");
        address desk = vm.envAddress("STREAM_G_SPONSORED_BUY_DESK");
        address gateway = vm.envAddress("STREAM_G_GOAT_RELAY_GATEWAY");
        address quoteSigner = vm.envAddress("STREAM_G_QUOTE_SIGNER");
        bytes32 deploymentManifestHash = vm.envBytes32("STREAM_G_DEPLOYMENT_MANIFEST_HASH");
        bytes32 feeScheduleHash = vm.envBytes32("STREAM_G_FEE_SCHEDULE_HASH");
        bool unpause = vm.envOr("STREAM_G_UNPAUSE", false);

        if (
            feeRegistry == address(0) || sidecar == address(0) || desk == address(0) || gateway == address(0)
                || quoteSigner == address(0)
        ) {
            revert ZeroAddress();
        }

        uint256 pk = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0));
        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();

        FeeTokenRegistry(feeRegistry).setRoleCommitment(
            FeeTokenRegistry(feeRegistry).ROLE_GATEWAY(), gateway, gateway.codehash
        );
        FeeTokenRegistry(feeRegistry).setRoleCommitment(
            FeeTokenRegistry(feeRegistry).ROLE_SPONSORED_BUY_DESK(), desk, desk.codehash
        );
        FeeTokenRegistry(feeRegistry).setActiveManifestHash(deploymentManifestHash);

        if (WalletSponsorshipRegistry(sidecar).gateway() == address(0)) {
            WalletSponsorshipRegistry(sidecar).bindGatewayOnce(gateway);
        }
        if (!SponsoredBuyDesk(desk).gatewayBound()) {
            SponsoredBuyDesk(desk).bindGatewayOnce(gateway);
        }

        GoatRelayGateway g = GoatRelayGateway(gateway);
        g.setFeeScheduleHash(feeScheduleHash);
        g.setQuoteSigner(quoteSigner);
        if (g.sponsoredBuyDesk() == address(0)) {
            g.setSponsoredBuyDesk(desk);
        }
        if (!g.activated()) {
            g.activate();
        }
        if (unpause) {
            g.setPaused(false);
        }

        vm.stopBroadcast();
        console.log("Stream G published/activated", gateway);
    }
}
