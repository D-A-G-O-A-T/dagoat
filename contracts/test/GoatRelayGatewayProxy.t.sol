// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {FeeTokenRegistry} from "../src/FeeTokenRegistry.sol";
import {WalletSponsorshipRegistry} from "../src/WalletSponsorshipRegistry.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";

/// Residential-proxy wiring on `GoatRelayGateway`: the two one-shot bindings,
/// and the three action types the gateway now recognises.
///
/// ## Two claims this file deliberately does NOT make
///
/// The plan for this task also named `test_fee_schedule_payload_matches_the_derived_length`
/// and `test_fee_schedule_hash_changes_when_a_row_is_added`. Neither can live
/// here. Both need RFC 8785 canonicalisation, and this repository has a
/// standing decision (stated at `DeployStreamG.t.sol:316-322`) that Solidity
/// must not grow a second canonicaliser: a reimplementation would be a second
/// definition of "the canonical bytes" to keep in step with the Rust one, and
/// the only Solidity-shaped alternative -- pinning a literal against itself --
/// is an assertion that cannot fail. Both claims are made in
/// `contracts/test/StreamGManifest.test.mjs` (the derived length constant
/// `EXPECTED_FEE_SCHEDULE_BYTES`, and the two mutations that move the digest),
/// against the same fixture, in the language that already owns the JCS half of
/// the parity pair.
///
/// The plan also named `test_rust_and_solidity_action_type_discriminants_agree`.
/// There are no discriminants to agree on: `StreamGTypes` encodes action types
/// as `bytes32` keccak constants with no ordinal anywhere, and the Rust
/// `ActionType` has no `#[repr]` and no explicit discriminants, so its integer
/// values are compiler-chosen and appear in no encoding. The real cross-language
/// binding is `keccak256(<canonical string>)`, which is what
/// `test_proxy_action_type_constants_are_the_keccak_of_their_canonical_strings`
/// below pins on this side and `quotes.rs::tests::action_type_strings_pinned`
/// pins on the other.
contract GoatRelayGatewayProxyTest is Test {
    address internal policy;
    address internal feeSafe;
    address internal recovery;
    address internal notPolicy;

    EnrollmentRegistry internal v1;
    GoatCoin internal goat;
    FeeTokenRegistry internal feeRegistry;
    WalletSponsorshipRegistry internal sidecar;
    GoatRelayGateway internal gateway;

    address internal settlement;
    address internal consumerRegistry;

    function setUp() public {
        policy = address(this);
        feeSafe = makeAddr("feeSafe");
        recovery = makeAddr("recovery");
        notPolicy = makeAddr("notPolicy");

        v1 = new EnrollmentRegistry(policy);
        goat = new GoatCoin("GoatCoin", "GOAT", policy, v1);
        feeRegistry = new FeeTokenRegistry(policy);
        sidecar = new WalletSponsorshipRegistry(address(v1), address(feeRegistry), policy, recovery, 7 days);

        gateway =
            new GoatRelayGateway(address(v1), address(feeRegistry), address(sidecar), address(goat), policy, feeSafe);

        // Stand-ins for ProxyRevenueSettlement / ProxyConsumerRegistry. The
        // gateway stores plain addresses and calls neither, so a bare address
        // is the whole of what it can observe; using the real contracts here
        // would test their constructors, not this binding.
        settlement = makeAddr("proxyRevenueSettlement");
        consumerRegistry = makeAddr("proxyConsumerRegistry");
    }

    // -------------------------------------------------------------------------
    // The two bindings
    // -------------------------------------------------------------------------

    function test_setters_are_safe_only_and_bind_once() public {
        // "Safe-only" here is the POLICY Safe, not the fee Safe. Asserted for
        // both, because the gateway holds two Safe addresses and a setter
        // guarded by the wrong one would still look guarded.
        vm.prank(notPolicy);
        vm.expectRevert(GoatRelayGateway.NotPolicySafe.selector);
        gateway.setProxyRevenueSettlement(settlement);

        vm.prank(feeSafe);
        vm.expectRevert(GoatRelayGateway.NotPolicySafe.selector);
        gateway.setProxyRevenueSettlement(settlement);

        vm.prank(notPolicy);
        vm.expectRevert(GoatRelayGateway.NotPolicySafe.selector);
        gateway.setProxyConsumerRegistry(consumerRegistry);

        vm.prank(feeSafe);
        vm.expectRevert(GoatRelayGateway.NotPolicySafe.selector);
        gateway.setProxyConsumerRegistry(consumerRegistry);

        // A refused call must leave nothing behind.
        assertEq(gateway.proxyRevenueSettlement(), address(0));
        assertEq(gateway.proxyConsumerRegistry(), address(0));

        // Zero is refused before the bind-once check, so a zero call cannot be
        // used to burn the one shot.
        vm.prank(policy);
        vm.expectRevert(GoatRelayGateway.ZeroAddress.selector);
        gateway.setProxyRevenueSettlement(address(0));

        vm.prank(policy);
        vm.expectRevert(GoatRelayGateway.ZeroAddress.selector);
        gateway.setProxyConsumerRegistry(address(0));

        assertEq(gateway.proxyRevenueSettlement(), address(0));
        assertEq(gateway.proxyConsumerRegistry(), address(0));

        // The Policy Safe binds, once.
        vm.prank(policy);
        vm.expectEmit(true, false, false, true, address(gateway));
        emit GoatRelayGateway.ProxyRevenueSettlementSet(settlement);
        gateway.setProxyRevenueSettlement(settlement);

        vm.prank(policy);
        vm.expectEmit(true, false, false, true, address(gateway));
        emit GoatRelayGateway.ProxyConsumerRegistrySet(consumerRegistry);
        gateway.setProxyConsumerRegistry(consumerRegistry);

        // A second bind is refused even by the Policy Safe, and even when it
        // names the SAME address -- the point is that the value is frozen, not
        // that it disagrees.
        vm.prank(policy);
        vm.expectRevert(GoatRelayGateway.ProxyAlreadySet.selector);
        gateway.setProxyRevenueSettlement(makeAddr("otherSettlement"));

        vm.prank(policy);
        vm.expectRevert(GoatRelayGateway.ProxyAlreadySet.selector);
        gateway.setProxyRevenueSettlement(settlement);

        vm.prank(policy);
        vm.expectRevert(GoatRelayGateway.ProxyAlreadySet.selector);
        gateway.setProxyConsumerRegistry(makeAddr("otherRegistry"));

        vm.prank(policy);
        vm.expectRevert(GoatRelayGateway.ProxyAlreadySet.selector);
        gateway.setProxyConsumerRegistry(consumerRegistry);

        assertEq(gateway.proxyRevenueSettlement(), settlement);
        assertEq(gateway.proxyConsumerRegistry(), consumerRegistry);
    }

    function test_gateway_reports_the_proxy_addresses_after_wiring() public {
        assertEq(gateway.proxyRevenueSettlement(), address(0));
        assertEq(gateway.proxyConsumerRegistry(), address(0));

        // The two slots are independent: binding one must not populate, or
        // lock, the other.
        vm.prank(policy);
        gateway.setProxyRevenueSettlement(settlement);
        assertEq(gateway.proxyRevenueSettlement(), settlement);
        assertEq(gateway.proxyConsumerRegistry(), address(0));

        vm.prank(policy);
        gateway.setProxyConsumerRegistry(consumerRegistry);
        assertEq(gateway.proxyRevenueSettlement(), settlement);
        assertEq(gateway.proxyConsumerRegistry(), consumerRegistry);

        // Two different addresses, so a getter that returned the wrong slot
        // would be caught rather than coincidentally right.
        assertTrue(settlement != consumerRegistry);

        // Wiring is not activation: neither setter may flip the gateway live.
        assertEq(gateway.activated(), false);
        assertEq(gateway.paused(), true);
    }

    // -------------------------------------------------------------------------
    // The three action types
    // -------------------------------------------------------------------------

    function test_proxy_action_type_constants_are_the_keccak_of_their_canonical_strings() public pure {
        assertEq(StreamGTypes.ACTION_PROXY_CLAIM, keccak256("GOAT_STREAM_G_PROXY_CLAIM_V1"));
        assertEq(StreamGTypes.ACTION_PROXY_PROPOSE_BATCH, keccak256("GOAT_STREAM_G_PROXY_PROPOSE_BATCH_V1"));
        assertEq(StreamGTypes.ACTION_PROXY_CHALLENGE_BATCH, keccak256("GOAT_STREAM_G_PROXY_CHALLENGE_BATCH_V1"));

        // All seven must be pairwise distinct: two action types sharing a
        // digest would share a nonce namespace, and one signed intent would be
        // replayable as the other.
        bytes32[7] memory all = [
            StreamGTypes.ACTION_SPONSORED_ENROLLMENT,
            StreamGTypes.ACTION_SPONSORED_SELL,
            StreamGTypes.ACTION_GOAT_TRANSFER,
            StreamGTypes.ACTION_USDT_TRANSFER,
            StreamGTypes.ACTION_PROXY_CLAIM,
            StreamGTypes.ACTION_PROXY_PROPOSE_BATCH,
            StreamGTypes.ACTION_PROXY_CHALLENGE_BATCH
        ];
        for (uint256 i = 0; i < all.length; i++) {
            assertTrue(all[i] != bytes32(0));
            for (uint256 j = i + 1; j < all.length; j++) {
                assertTrue(all[i] != all[j]);
            }
        }
    }

    /// Recognition is the ONLY thing this task widened. `nonceSnapshot` stops
    /// refusing the three proxy action types; no `execute*` entrypoint accepts
    /// any of them, so none is sponsorable.
    function test_nonce_snapshot_recognises_the_three_proxy_action_types() public {
        address signer = makeAddr("signer");

        bytes32[3] memory added = [
            StreamGTypes.ACTION_PROXY_CLAIM,
            StreamGTypes.ACTION_PROXY_PROPOSE_BATCH,
            StreamGTypes.ACTION_PROXY_CHALLENGE_BATCH
        ];
        for (uint256 i = 0; i < added.length; i++) {
            StreamGTypes.NonceSnapshot memory snap =
                gateway.nonceSnapshot(added[i], signer, address(0), address(0), address(0));
            assertEq(snap.actionNonce, 0);
            assertEq(snap.blockNumber, uint64(block.number));
            assertTrue(snap.presentMask & StreamGTypes.SNAP_ACTION_NONCE != 0);
        }

        // ...and a bytes32 that is not the keccak of any canonical string is
        // still refused. Widening a recognised set is only safe if the refusal
        // it widens still exists.
        vm.expectRevert(GoatRelayGateway.UnknownActionType.selector);
        gateway.nonceSnapshot(bytes32(uint256(0xdead)), signer, address(0), address(0), address(0));

        // Near-misses too: the canonical string without its version suffix, and
        // the settlement function name a reader might reach for instead.
        vm.expectRevert(GoatRelayGateway.UnknownActionType.selector);
        gateway.nonceSnapshot(keccak256("GOAT_STREAM_G_PROXY_CLAIM"), signer, address(0), address(0), address(0));
        vm.expectRevert(GoatRelayGateway.UnknownActionType.selector);
        gateway.nonceSnapshot(keccak256("claim"), signer, address(0), address(0), address(0));
    }
}
