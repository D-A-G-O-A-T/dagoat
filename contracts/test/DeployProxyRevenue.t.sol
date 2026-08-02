// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployProxyRevenue} from "../script/DeployProxyRevenue.s.sol";
import {ProxyRevenueSettlement} from "../src/proxy/ProxyRevenueSettlement.sol";
import {ProxyConsumerRegistry} from "../src/proxy/ProxyConsumerRegistry.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {MockUSDT} from "./mocks/MockUSDT.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// Exposes the script's internal bound check so it can be asserted directly.
/// Subclassing rather than widening `DeployProxyRevenue`'s own surface: a
/// `public` helper on a deploy script is a function an operator can call.
contract DeployProxyRevenueHarness is DeployProxyRevenue {
    function exposedU64(uint256 v) external pure returns (uint64) {
        return _u64(v);
    }
}

/// Post-deploy assertions for the proxy revenue pair.
///
/// Two properties are being defended here and they fail differently. The first is
/// that the deployed pair is internally consistent — the split adds up, the
/// counters start at zero, the settlement holds no minter role. The second is that
/// the PUBLISHED artifact still describes the bytecode it names, because an
/// off-chain aggregator's configurable take is checked against
/// `<chainid>.proxy.json` and nothing else would notice the two drifting apart.
///
/// Only ONE test in this contract writes the artifact. `forge` runs a contract's
/// test functions concurrently and `vm.writeJson` truncates before it writes, so a
/// second writer would let the reader observe the file empty and report it as
/// `EOF while parsing a value at line 1 column 0` — a phantom flake, which is
/// worse than a red test because it becomes a standing licence to dismiss the
/// signal. Every other test passes `writeManifest: false`.
///
/// That same test is also the only one that touches the process environment. It
/// sets the `PROXY_*` variables immediately before calling `run()` rather than in
/// `setUp`, because `vm.setEnv` mutates the REAL process environment shared by
/// every concurrently-running test: a `setUp` that published `address(goat)` from
/// its own EVM instance would let another instance's `run()` read an address that
/// does not exist in its state.
contract DeployProxyRevenueTest is Test {
    DeployProxyRevenue script;
    DeployProxyRevenueHarness harness;
    EnrollmentRegistry reg;
    GoatCoin goat;
    MockUSDT stakeToken;

    address safe = makeAddr("policySafe");
    address treasury = makeAddr("protocolTreasury");
    address attestorSafe = makeAddr("attestorSafe");
    address reserveSink = makeAddr("reserveSink");
    address funder = makeAddr("funder");
    address publisher = makeAddr("publisher");
    address gateway = makeAddr("goatRelayGateway");
    address usdtTreasury = makeAddr("usdtTreasury");
    address disputeResolver = makeAddr("disputeResolver");
    address watcher = makeAddr("watcher");
    address operator = makeAddr("operator");

    uint64 constant CHALLENGE_WINDOW = 12 hours;
    uint64 constant CLAIM_WINDOW = 30 days;
    uint64 constant RESOLVE_WINDOW = 3 days;
    uint256 constant PROPOSER_BOND = 0.01 ether;
    uint256 constant CHALLENGER_BOND = 0.01 ether;
    /// USDT-wei of backing required per GOAT-wei funded. Bounds funding against
    /// realized inflow; it is not a price and not a peg.
    uint256 constant REFERENCE_RATE = 1e15;
    uint256 constant MIN_STAKE = 1_000e6;
    uint64 constant UNSTAKE_DELAY = 3 days;
    uint256 constant DEPLOYER_PK = 0xA11CE;

    function setUp() public {
        script = new DeployProxyRevenue();
        harness = new DeployProxyRevenueHarness();
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        stakeToken = new MockUSDT();
    }

    // ------------------------------------------------------------------ helpers

    function _params() internal view returns (DeployProxyRevenue.Params memory p) {
        p.settlement = ProxyRevenueSettlement.Config({
            safe: safe,
            goat: address(goat),
            registry: address(reg),
            treasury: treasury,
            attestorSafe: attestorSafe,
            reserveSink: reserveSink,
            funder: funder,
            publisher: publisher,
            gateway: gateway,
            usdtTreasury: usdtTreasury,
            resolver: disputeResolver,
            watcher: watcher,
            challengeWindow: CHALLENGE_WINDOW,
            claimWindow: CLAIM_WINDOW,
            resolveWindow: RESOLVE_WINDOW,
            proposerBond: PROPOSER_BOND,
            challengerBond: CHALLENGER_BOND,
            referenceRateUsdtPerGoat: REFERENCE_RATE
        });
        p.stakeToken = address(stakeToken);
        p.minStake = MIN_STAKE;
        p.unstakeDelay = UNSTAKE_DELAY;
        p.writeManifest = false;
        p.manifestPath = "";
    }

    function _deploySilently()
        internal
        returns (ProxyRevenueSettlement s, ProxyConsumerRegistry c)
    {
        DeployProxyRevenue.Deployed memory d = script.deploy(_params());
        s = ProxyRevenueSettlement(payable(d.proxyRevenueSettlement));
        c = ProxyConsumerRegistry(d.proxyConsumerRegistry);
    }

    /// Read an artifact the script just wrote, failing with a message that names the
    /// file and the likely cause. `vm.parseJsonUint` reports an absent or truncated
    /// file as a bare parser error that names neither, and reads exactly like a
    /// flaky test.
    function _readArtifact(string memory path) internal view returns (string memory json) {
        json = vm.readFile(path);
        require(
            bytes(json).length > 0,
            string.concat(
                "proxy deployment artifact is EMPTY at ",
                path,
                " -- the script did not reach vm.writeJson, or another process truncated it."
            )
        );
    }

    // -------------------------------------------------------------------- tests

    /// Eleven facts, each read back from the deployed contracts. A deploy that
    /// leaves any of them wrong is a deploy that must not be used.
    ///
    /// Mutations this detects:
    ///  - any edit to the four take constants that stops them summing to the take,
    ///    or to `OPERATOR_BPS + TAKE_BPS` summing to `BPS_DENOM`;
    ///  - a script that pre-funds, pre-books the reserve, or leaves a counter
    ///    non-zero at deploy;
    ///  - a script that grants the settlement a minter role;
    ///  - `PROXY_MIN_STAKE` allowed to fall through to zero, i.e. a free credential;
    ///  - a change to the leaf domain preimage, which would silently orphan every
    ///    proof the off-chain aggregator produces;
    ///  - a reference rate or resolve window of zero, which makes the funding bound
    ///    vacuous and `timeoutChallenge` instant.
    function test_deployed_wiring_reads_back_correctly() public {
        (ProxyRevenueSettlement s, ProxyConsumerRegistry c) = _deploySilently();

        assertEq(uint256(s.OPERATOR_BPS()) + s.TAKE_BPS(), uint256(s.BPS_DENOM()));
        assertEq(uint256(s.TAKE_BPS()), 1_000);
        assertEq(
            uint256(s.TREASURY_BPS()) + s.ATTESTOR_BPS() + s.RESERVE_BPS(), uint256(s.TAKE_BPS())
        );
        assertEq(s.totalFunded(), 0);
        assertEq(s.totalClaimed(), 0);
        assertEq(s.reserveHeld(), 0);
        assertFalse(goat.isMinter(address(s)), "the settlement was granted a minter role");
        assertTrue(c.minStake() > 0, "a zero floor is a free credential, not collateral");
        assertEq(s.PROXY_LEAF_DOMAIN(), keccak256("GOAT_PROXY_REVENUE_LEAF_V1"));
        assertTrue(
            s.referenceRateUsdtPerGoat() > 0, "a zero rate makes the funding bound vacuous"
        );
        assertTrue(s.resolveWindow() > 0, "a zero resolve window makes timeoutChallenge instant");
    }

    /// The off-chain aggregator's take is configurable; the on-chain `TAKE_BPS` is
    /// immutable. Nothing asserted that they agree, so a config edit could move
    /// basis points of gross from operators to the treasury with every test green.
    /// The deployment artifact is the seam where they meet, so the artifact has to
    /// describe the bytecode it names.
    ///
    /// This is the ONE test that drives `run()` through the environment and the ONE
    /// test that writes the canonical artifact — see the contract doc for why both
    /// are singular.
    ///
    /// Mutations this detects:
    ///  - any `takeBps`/`operatorBps`/`treasuryBps`/`attestorBps`/`reserveBps`
    ///    written to the artifact as a literal instead of read off the deployment;
    ///  - a renamed or misspelled env variable in `_paramsFromEnv`, which would
    ///    either revert or bind the wrong address into a published field;
    ///  - a `vm.writeJson` dropped from `deploy`, or written to a path that is not
    ///    chain-scoped;
    ///  - the settlement and the registry addresses swapped in the artifact.
    function test_deployed_take_matches_the_published_artifact() public {
        vm.setEnv("POLICY_SAFE", vm.toString(safe));
        vm.setEnv("GOAT_COIN", vm.toString(address(goat)));
        vm.setEnv("ENROLLMENT_REGISTRY", vm.toString(address(reg)));
        vm.setEnv("PROXY_PROTOCOL_TREASURY", vm.toString(treasury));
        vm.setEnv("PROXY_ATTESTOR_SAFE", vm.toString(attestorSafe));
        vm.setEnv("PROXY_RESERVE_SINK", vm.toString(reserveSink));
        vm.setEnv("PROXY_FUNDER", vm.toString(funder));
        vm.setEnv("PROXY_PUBLISHER", vm.toString(publisher));
        vm.setEnv("GOAT_RELAY_GATEWAY", vm.toString(gateway));
        vm.setEnv("PROXY_USDT_TREASURY", vm.toString(usdtTreasury));
        vm.setEnv("DISPUTE_RESOLVER", vm.toString(disputeResolver));
        vm.setEnv("PROXY_WATCHER", vm.toString(watcher));
        vm.setEnv("PROXY_STAKE_TOKEN", vm.toString(address(stakeToken)));
        vm.setEnv("PROXY_CHALLENGE_WINDOW", vm.toString(uint256(CHALLENGE_WINDOW)));
        vm.setEnv("PROXY_CLAIM_WINDOW", vm.toString(uint256(CLAIM_WINDOW)));
        vm.setEnv("PROXY_RESOLVE_WINDOW", vm.toString(uint256(RESOLVE_WINDOW)));
        vm.setEnv("PROXY_PROPOSER_BOND", vm.toString(PROPOSER_BOND));
        vm.setEnv("PROXY_CHALLENGER_BOND", vm.toString(CHALLENGER_BOND));
        vm.setEnv("PROXY_REFERENCE_RATE", vm.toString(REFERENCE_RATE));
        vm.setEnv("PROXY_MIN_STAKE", vm.toString(MIN_STAKE));
        vm.setEnv("PROXY_UNSTAKE_DELAY", vm.toString(uint256(UNSTAKE_DELAY)));
        vm.setEnv("DEPLOYER_PRIVATE_KEY", vm.toString(DEPLOYER_PK));

        DeployProxyRevenue.Deployed memory d = script.run();
        ProxyRevenueSettlement s = ProxyRevenueSettlement(payable(d.proxyRevenueSettlement));

        string memory json = _readArtifact(script.defaultManifestPath());

        assertEq(
            vm.parseJsonUint(json, ".takeBps"),
            uint256(s.TAKE_BPS()),
            "artifact take != on-chain TAKE_BPS"
        );
        assertEq(vm.parseJsonUint(json, ".operatorBps"), uint256(s.OPERATOR_BPS()));
        assertEq(vm.parseJsonUint(json, ".treasuryBps"), uint256(s.TREASURY_BPS()));
        assertEq(vm.parseJsonUint(json, ".attestorBps"), uint256(s.ATTESTOR_BPS()));
        assertEq(vm.parseJsonUint(json, ".reserveBps"), uint256(s.RESERVE_BPS()));
        assertEq(vm.parseJsonUint(json, ".bpsDenominator"), uint256(s.BPS_DENOM()));
        assertEq(vm.parseJsonUint(json, ".proxyEpochBase"), s.PROXY_EPOCH_BASE());
        assertEq(vm.parseJsonUint(json, ".proxyEpochCeiling"), s.PROXY_EPOCH_CEILING());
        assertEq(vm.parseJsonUint(json, ".chainId"), block.chainid);

        assertEq(
            vm.parseJsonAddress(json, ".proxyRevenueSettlement"), d.proxyRevenueSettlement
        );
        assertEq(vm.parseJsonAddress(json, ".proxyConsumerRegistry"), d.proxyConsumerRegistry);
        assertEq(vm.parseJsonAddress(json, ".enrollmentRegistry"), address(reg));
        assertEq(vm.parseJsonAddress(json, ".goatCoin"), address(goat));
        assertEq(vm.parseJsonAddress(json, ".protocolTreasury"), treasury);
        assertEq(vm.parseJsonAddress(json, ".attestorSafe"), attestorSafe);
        assertEq(vm.parseJsonAddress(json, ".reserveSink"), reserveSink);
        assertEq(vm.parseJsonAddress(json, ".goatRelayGateway"), gateway);
        assertEq(vm.parseJsonAddress(json, ".usdtTreasury"), usdtTreasury);
        assertEq(vm.parseJsonAddress(json, ".disputeResolver"), disputeResolver);
        assertEq(vm.parseJsonAddress(json, ".stakeToken"), address(stakeToken));

        // The windows and bonds are published from the deployment too, so an
        // operator reading the artifact reads the values the contract enforces.
        assertEq(vm.parseJsonUint(json, ".challengeWindow"), uint256(s.challengeWindow()));
        assertEq(vm.parseJsonUint(json, ".claimWindow"), uint256(s.claimWindow()));
        assertEq(vm.parseJsonUint(json, ".resolveWindow"), uint256(s.resolveWindow()));
        assertEq(vm.parseJsonUint(json, ".proposerBond"), s.proposerBond());
        assertEq(vm.parseJsonUint(json, ".challengerBond"), s.challengerBond());
        assertEq(
            vm.parseJsonUint(json, ".referenceRateUsdtPerGoat"), s.referenceRateUsdtPerGoat()
        );
    }

    /// The settlement must be able to send GOAT, which under the pilot's transfer
    /// restriction means it and every take destination must be on the allowlist —
    /// otherwise every payout reverts `TransferRestricted` and the failure appears
    /// at the first claim rather than at the deploy that caused it.
    ///
    /// The script cannot perform that wiring: `setEnrolled` is `onlySafe` on a
    /// registry this deploy did not create. So it prints it, and this test performs
    /// exactly the printed list and shows a transfer that fails before it succeeds
    /// after. Both halves are required: without the negative half the test would
    /// also pass against a token with no restriction at all.
    ///
    /// Mutations this detects:
    ///  - dropping any of the four `setEnrolled` lines from the printed wiring
    ///    (this test's list is the executable copy of that list);
    ///  - a future edit that lifts the transfer restriction and makes the wiring
    ///    look unnecessary, which would flip the negative half red.
    function test_a_payout_transfer_needs_the_printed_safe_wiring() public {
        (ProxyRevenueSettlement s,) = _deploySilently();

        vm.prank(safe);
        goat.setMinter(address(this), true);
        goat.mint(address(s), 100e18);
        assertEq(goat.balanceOf(address(s)), 100e18);

        // Negative half: unwired, the settlement cannot move a single wei out.
        vm.prank(address(s));
        vm.expectRevert(GoatCoin.TransferRestricted.selector);
        goat.transfer(treasury, 1e18);

        // Exactly the calls the script prints, as the Safe would submit them.
        vm.startPrank(safe);
        reg.setEnrolled(address(s), true, bytes32(0));
        reg.setEnrolled(treasury, true, bytes32(0));
        reg.setEnrolled(attestorSafe, true, bytes32(0));
        reg.setEnrolled(reserveSink, true, bytes32(0));
        reg.setEnrolled(operator, true, keccak256("operator-record"));
        vm.stopPrank();

        // Positive half: the same transfer now lands, and so does an operator payout.
        vm.startPrank(address(s));
        goat.transfer(treasury, 1e18);
        goat.transfer(attestorSafe, 1e18);
        goat.transfer(reserveSink, 1e18);
        goat.transfer(operator, 1e18);
        vm.stopPrank();

        assertEq(goat.balanceOf(treasury), 1e18);
        assertEq(goat.balanceOf(attestorSafe), 1e18);
        assertEq(goat.balanceOf(reserveSink), 1e18);
        assertEq(goat.balanceOf(operator), 1e18);
    }

    /// The two contracts are deployed from ONE parameter set on purpose. A slash
    /// that credited a different sink from the one the reserve pays out of, or a
    /// consumer registry composed with a different allowlist from the one the payout
    /// path reads, would be a two-address split that no single-contract test could
    /// see.
    ///
    /// Mutations this detects: passing a second, separately-sourced reserve sink,
    /// allowlist or Safe into either constructor in `deploy`.
    function test_both_contracts_share_one_safe_allowlist_and_reserve_sink() public {
        (ProxyRevenueSettlement s, ProxyConsumerRegistry c) = _deploySilently();

        assertEq(c.safe(), s.safe());
        assertEq(address(c.registry()), s.registry());
        assertEq(c.reserveSink(), s.reserveSink());

        assertEq(c.safe(), safe);
        assertEq(address(c.registry()), address(reg));
        assertEq(c.reserveSink(), reserveSink);
    }

    /// Consumer collateral is not the payout asset. If the stake token were GOAT,
    /// a slash would move payout inventory and the collateral's value would track
    /// the thing it is meant to be collateral against.
    ///
    /// Mutations this detects: passing `p.settlement.goat` as the registry's stake
    /// token in `deploy`.
    function test_consumer_collateral_is_not_the_payout_token() public {
        (ProxyRevenueSettlement s, ProxyConsumerRegistry c) = _deploySilently();

        IERC20 collateral = c.stakeToken();
        IERC20 payoutToken = s.goat();

        assertTrue(address(collateral) != address(payoutToken), "collateral is the payout token");
        assertEq(address(collateral), address(stakeToken));
        assertEq(address(payoutToken), address(goat));
    }

    /// Anvil only. A chain id this lane has not been reviewed on is a refusal, and
    /// Base Sepolia gets its own error so an operator who tried it reads "gated"
    /// rather than "unknown chain".
    ///
    /// Mutations this detects: widening `_assertChainAllowed` to admit 84532 or to
    /// admit any chain id, and reordering the two checks so 84532 reports the
    /// generic refusal.
    function test_deploy_refuses_every_chain_except_anvil() public {
        DeployProxyRevenue.Params memory p = _params();

        vm.chainId(84532);
        vm.expectRevert(DeployProxyRevenue.BaseSepoliaPhaseGated.selector);
        script.deploy(p);

        vm.chainId(1);
        vm.expectRevert(DeployProxyRevenue.ChainNotAllowed.selector);
        script.deploy(p);

        vm.chainId(8453);
        vm.expectRevert(DeployProxyRevenue.ChainNotAllowed.selector);
        script.deploy(p);

        // Positive control: the same parameters deploy on Anvil, so the three
        // refusals above cannot be coming from a script that refuses everything.
        vm.chainId(31337);
        DeployProxyRevenue.Deployed memory d = script.deploy(p);
        assertTrue(d.proxyRevenueSettlement != address(0));
        assertTrue(d.proxyConsumerRegistry != address(0));
    }

    /// The artifact path carries the chain id, so a deploy on one chain can never
    /// overwrite another chain's published addresses.
    ///
    /// Mutations this detects: a hard-coded `31337` in the path, or dropping the
    /// chain id segment entirely.
    function test_the_artifact_path_is_chain_scoped() public {
        assertEq(script.defaultManifestPath(), "./deployments/31337.proxy.json");
        vm.chainId(84532);
        assertEq(script.defaultManifestPath(), "./deployments/84532.proxy.json");
        vm.chainId(31337);
    }

    /// A window that does not fit in 64 bits is a refusal, not a silent truncation.
    /// `uint64(2**64)` is zero, and a zero resolve window makes `timeoutChallenge`
    /// instant — a bug that would look exactly like a deliberate setting.
    ///
    /// Mutations this detects: replacing `_u64` with a bare `uint64(...)` cast in
    /// `_paramsFromEnv`.
    function test_an_oversized_window_is_refused_not_truncated() public {
        // Positive control first: the largest value that does fit is accepted.
        assertEq(harness.exposedU64(type(uint64).max), type(uint64).max);

        vm.expectRevert(DeployProxyRevenue.ValueTooLarge.selector);
        harness.exposedU64(uint256(type(uint64).max) + 1);
    }
}
