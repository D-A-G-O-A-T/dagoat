// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ProxyRevenueSettlement} from "../src/proxy/ProxyRevenueSettlement.sol";
import {ProxyConsumerRegistry} from "../src/proxy/ProxyConsumerRegistry.sol";

/// Anvil-only deploy of the proxy revenue pair: `ProxyRevenueSettlement` and
/// `ProxyConsumerRegistry`. [TARGET]
///
/// # Every money-path value is required and has no default
///
/// `run()` reads each address and each window through `vm.envAddress` /
/// `vm.envUint`, never `vm.envOr`. A deploy that cannot name its treasury, its
/// attestor safe or its reserve sink is a deploy that must FAIL, not one that
/// quietly picks an address. The two contracts refuse a zero address in their
/// constructors, so a variable set to `0x0` is caught one layer further in; the
/// missing-variable case is caught here, before any contract is created.
///
/// `uint64` fields go through `_u64`, which reverts rather than truncating. A
/// silent truncation of a window to zero would make `timeoutChallenge` instant
/// and the consumer exit delay vacuous, and nothing downstream could tell that
/// apart from a deliberate zero.
///
/// # This script performs no Safe-gated call, and that is deliberate
///
/// `EnrollmentRegistry.setEnrolled` and `GoatCoin.setMinter` are `onlySafe`, and
/// the registry and the token are pre-existing contracts owned by a Safe that is
/// not the deploying wallet. A script that called them would revert `NotSafe` on
/// every real deploy. So the wiring is PRINTED, not performed, and
/// `DeployProxyRevenue.t.sol` performs exactly the printed list and then proves a
/// payout transfer that failed before it succeeds after.
///
/// One line of that printed list is a prohibition rather than a step: the
/// settlement must never be given a minter role. It moves GOAT that already
/// exists and creates none, and a test reads `isMinter` back off the token to
/// assert the deploy left it false.
///
/// # No call is made on `GoatRelayGateway`
///
/// The gateway address is a CONSTRUCTOR argument of the settlement, which is what
/// authorises the gateway to call `recordUsdtInflow`. That authorisation is
/// one-directional and needs no transaction against the gateway. The gateway is
/// therefore recorded in the artifact and named in the printed wiring, and this
/// script sends it nothing.
///
/// Corrected 2026-07-31: this said `GoatRelayGateway` "exposes no proxy-binding
/// setter to call". It now exposes two -- `setProxyRevenueSettlement` and
/// `setProxyConsumerRegistry` -- and both are `onlyPolicy`, so neither is a
/// call this script's deployer key could make anyway. Wiring them is a Policy
/// Safe transaction, and belongs to the task that owns the reverse binding.
///
/// # The artifact
///
/// `./deployments/<chainid>.proxy.json` — addresses and integers only, no strings,
/// because `contracts/deployments` is swept as text by the citation audit. Every
/// basis-point field is READ BACK off the deployed settlement rather than written
/// from a literal here, so the published `takeBps` cannot drift from the immutable
/// `TAKE_BPS()` in the bytecode it describes. That is the seam an off-chain
/// aggregator's configurable take is checked against.
contract DeployProxyRevenue is Script {
    error ChainNotAllowed();
    error BaseSepoliaPhaseGated();
    error ValueTooLarge();

    /// Everything the pair needs. `settlement` is the settlement's own `Config`
    /// struct rather than a re-listing of its eighteen fields: a second copy of a
    /// field list is a second thing to keep in step, and the pairing that matters
    /// (`reserveSink`, `registry` and `safe` shared with the consumer registry) is
    /// then a read of one struct instead of an equality between two.
    struct Params {
        ProxyRevenueSettlement.Config settlement;
        /// Consumer collateral token. Never GOAT.
        address stakeToken;
        uint256 minStake;
        uint64 unstakeDelay;
        /// False in unit tests that do not assert on the published document, so
        /// exactly ONE test in the suite writes the canonical artifact. `forge`
        /// runs a contract's test functions concurrently and `vm.writeJson`
        /// truncates before it writes, so a second writer would let a reader
        /// observe the file empty.
        bool writeManifest;
        /// Per-CALL override of the artifact path. Empty means
        /// `defaultManifestPath()`. On the stack, so it cannot leak into another
        /// concurrently-running test the way `vm.setEnv` would.
        string manifestPath;
    }

    struct Deployed {
        address proxyRevenueSettlement;
        address proxyConsumerRegistry;
    }

    function run() external returns (Deployed memory d) {
        _assertChainAllowed(block.chainid);
        Params memory p = _paramsFromEnv();

        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(pk);
        d = deploy(p);
        vm.stopBroadcast();

        _logWiring(p, d);
    }

    function defaultManifestPath() public view returns (string memory) {
        return string.concat("./deployments/", vm.toString(block.chainid), ".proxy.json");
    }

    /// Chain-gated deploy used by both `run()` and the unit tests. Tests build
    /// `Params` on the stack and never touch the process environment.
    function deploy(Params memory p) public returns (Deployed memory d) {
        _assertChainAllowed(block.chainid);

        // The consumer registry first: it takes its allowlist and its slash
        // destination from the same fields the settlement takes, so the two
        // cannot be pointed at different reserve sinks by a typo in one of them.
        ProxyConsumerRegistry c = new ProxyConsumerRegistry(
            p.settlement.safe, p.stakeToken, p.settlement.registry, p.settlement.reserveSink, p.minStake, p.unstakeDelay
        );
        ProxyRevenueSettlement s = new ProxyRevenueSettlement(p.settlement);

        d = Deployed({proxyRevenueSettlement: address(s), proxyConsumerRegistry: address(c)});

        if (p.writeManifest) {
            _writeManifest(p, s, c, _resolveManifestPath(p.manifestPath));
        }
    }

    function _paramsFromEnv() internal view returns (Params memory p) {
        // Read once and shared, so the registry's slash destination and the
        // settlement's reserve are the same address by construction.
        address reserveSink = vm.envAddress("PROXY_RESERVE_SINK");

        p.settlement = ProxyRevenueSettlement.Config({
            safe: vm.envAddress("POLICY_SAFE"),
            goat: vm.envAddress("GOAT_COIN"),
            registry: vm.envAddress("ENROLLMENT_REGISTRY"),
            treasury: vm.envAddress("PROXY_PROTOCOL_TREASURY"),
            attestorSafe: vm.envAddress("PROXY_ATTESTOR_SAFE"),
            reserveSink: reserveSink,
            funder: vm.envAddress("PROXY_FUNDER"),
            publisher: vm.envAddress("PROXY_PUBLISHER"),
            gateway: vm.envAddress("GOAT_RELAY_GATEWAY"),
            usdtTreasury: vm.envAddress("PROXY_USDT_TREASURY"),
            resolver: vm.envAddress("DISPUTE_RESOLVER"),
            watcher: vm.envAddress("PROXY_WATCHER"),
            challengeWindow: _u64(vm.envUint("PROXY_CHALLENGE_WINDOW")),
            claimWindow: _u64(vm.envUint("PROXY_CLAIM_WINDOW")),
            resolveWindow: _u64(vm.envUint("PROXY_RESOLVE_WINDOW")),
            proposerBond: vm.envUint("PROXY_PROPOSER_BOND"),
            challengerBond: vm.envUint("PROXY_CHALLENGER_BOND"),
            referenceRateUsdtPerGoat: vm.envUint("PROXY_REFERENCE_RATE")
        });

        p.stakeToken = vm.envAddress("PROXY_STAKE_TOKEN");
        p.minStake = vm.envUint("PROXY_MIN_STAKE");
        p.unstakeDelay = _u64(vm.envUint("PROXY_UNSTAKE_DELAY"));
        p.writeManifest = true;
        p.manifestPath = "";
    }

    function _resolveManifestPath(string memory pathOverride) internal view returns (string memory) {
        if (bytes(pathOverride).length != 0) return pathOverride;
        return defaultManifestPath();
    }

    /// Addresses and integers only. No string value is written anywhere in this
    /// document: `contracts/deployments` is read as text by the citation sweep, and
    /// a free-text field in a machine-written file is a place for a stale claim to
    /// live where nothing regenerates it.
    function _writeManifest(Params memory p, ProxyRevenueSettlement s, ProxyConsumerRegistry c, string memory path)
        internal
    {
        if (block.chainid != 31337) revert ChainNotAllowed();

        string memory k = "proxy";
        vm.serializeUint(k, "schemaVersion", uint256(1));
        vm.serializeUint(k, "chainId", block.chainid);

        vm.serializeAddress(k, "proxyRevenueSettlement", address(s));
        vm.serializeAddress(k, "proxyConsumerRegistry", address(c));
        vm.serializeAddress(k, "policySafe", p.settlement.safe);
        vm.serializeAddress(k, "goatCoin", p.settlement.goat);
        vm.serializeAddress(k, "enrollmentRegistry", p.settlement.registry);
        vm.serializeAddress(k, "protocolTreasury", p.settlement.treasury);
        vm.serializeAddress(k, "attestorSafe", p.settlement.attestorSafe);
        vm.serializeAddress(k, "reserveSink", p.settlement.reserveSink);
        vm.serializeAddress(k, "funder", p.settlement.funder);
        vm.serializeAddress(k, "publisher", p.settlement.publisher);
        vm.serializeAddress(k, "goatRelayGateway", p.settlement.gateway);
        vm.serializeAddress(k, "usdtTreasury", p.settlement.usdtTreasury);
        vm.serializeAddress(k, "disputeResolver", p.settlement.resolver);
        vm.serializeAddress(k, "watcher", p.settlement.watcher);
        vm.serializeAddress(k, "stakeToken", p.stakeToken);

        // Read off the deployed runtime, never from a literal here. This is the
        // whole reason the artifact can be used to check an off-chain take.
        vm.serializeUint(k, "operatorBps", uint256(s.OPERATOR_BPS()));
        vm.serializeUint(k, "takeBps", uint256(s.TAKE_BPS()));
        vm.serializeUint(k, "treasuryBps", uint256(s.TREASURY_BPS()));
        vm.serializeUint(k, "attestorBps", uint256(s.ATTESTOR_BPS()));
        vm.serializeUint(k, "reserveBps", uint256(s.RESERVE_BPS()));
        vm.serializeUint(k, "bpsDenominator", uint256(s.BPS_DENOM()));
        vm.serializeUint(k, "proxyEpochBase", s.PROXY_EPOCH_BASE());
        vm.serializeUint(k, "proxyEpochCeiling", s.PROXY_EPOCH_CEILING());

        vm.serializeUint(k, "challengeWindow", uint256(s.challengeWindow()));
        vm.serializeUint(k, "claimWindow", uint256(s.claimWindow()));
        vm.serializeUint(k, "resolveWindow", uint256(s.resolveWindow()));
        vm.serializeUint(k, "proposerBond", s.proposerBond());
        vm.serializeUint(k, "challengerBond", s.challengerBond());
        vm.serializeUint(k, "referenceRateUsdtPerGoat", s.referenceRateUsdtPerGoat());
        vm.serializeUint(k, "minStake", c.minStake());
        string memory j = vm.serializeUint(k, "unstakeDelay", uint256(c.unstakeDelay()));

        vm.writeJson(j, path);
    }

    /// The Policy Safe transactions this deploy does NOT make. Printed rather than
    /// performed because every one of them is `onlySafe` on a contract this deploy
    /// did not create — see the contract doc.
    function _logWiring(Params memory p, Deployed memory d) internal view {
        console.log("proxyRevenueSettlement:", d.proxyRevenueSettlement);
        console.log("proxyConsumerRegistry: ", d.proxyConsumerRegistry);
        console.log("artifact:              ", _resolveManifestPath(p.manifestPath));
        console.log("NEXT, from the Policy Safe. This script performs NONE of these:");
        console.log("  registry.setEnrolled(proxyRevenueSettlement, true, 0x0)");
        console.log("  registry.setEnrolled(protocolTreasury, true, 0x0)");
        console.log("  registry.setEnrolled(attestorSafe, true, 0x0)");
        console.log("  registry.setEnrolled(reserveSink, true, 0x0)");
        console.log("  registry.setEnrolled(<each operator>, true, <record hash>)");
        console.log("  consumerRegistry.enrolConsumer(<consumer>, <record hash>)");
        console.log("Without the first four, every payout transfer reverts TransferRestricted");
        console.log("and the failure surfaces at the first claim rather than at this deploy.");
        console.log("NEVER: goat.setMinter(proxyRevenueSettlement, true)");
        console.log("This lane moves GOAT that already exists and creates no new supply.");
    }

    /// A window that does not fit is a refusal, not a truncation.
    function _u64(uint256 v) internal pure returns (uint64) {
        if (v > type(uint64).max) revert ValueTooLarge();
        return uint64(v);
    }

    function _assertChainAllowed(uint256 chainId) internal pure {
        if (chainId == 84532) revert BaseSepoliaPhaseGated();
        if (chainId != 31337) revert ChainNotAllowed();
    }
}
