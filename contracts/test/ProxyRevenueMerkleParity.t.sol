// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {ProxyRevenueSettlement} from "../src/proxy/ProxyRevenueSettlement.sol";

/// Cross-language parity for the fetch-network settlement lane. Constants pinned
/// from `cargo test --lib proxy::proxy_merkle::tests::pinned_proxy_solidity_cross_check_vectors`.
///
/// If these fail, Rust leaf hashing has drifted from Solidity and every
/// daemon-produced proof will BadProof on chain. The pin is the only thing that
/// says so before a deploy does, which is why it is asserted in both languages
/// against the same literals rather than derived once and shared.
contract ProxyRevenueMerkleParityTest is Test {
    bytes32 constant DOMAIN = keccak256("GOAT_PROXY_REVENUE_LEAF_V1");

    address constant OP_A = address(uint160(0xA1));
    address constant OP_B = address(uint160(0xB2));
    uint256 constant EPOCH = 8_000_000_020_664;

    // ---- pinned from the attestor's Rust tests (Step 3) ----
    uint256 constant BYTES_A = 1_073_741_824;
    uint256 constant AMT_A = 250_000_000_000_000_000;
    uint256 constant BYTES_B = 1;
    uint256 constant AMT_B = 232_830_643;
    uint256 constant BYTES_C = 4_294_967_296;
    uint256 constant AMT_C = 1_000_000_000_000_000_000;

    bytes32 constant LEAF_A = 0x231e1232b6f86534b6c979a68e95c2d22dadfe390c6129ea50d3ae5de1b4f4cd;
    bytes32 constant LEAF_B = 0x8dc20ea0c0ab4e2a08cfa61064e44ec8045f320589659b3ee3cc8e331f439508;
    bytes32 constant LEAF_C = 0xb488ac365921e6abce7f8ee2a6258769fe4ed9c5fbcbc02b6d60ce9262930e62;
    bytes32 constant TWO_LEAF_ROOT = 0xad9982dfabd1dd84bd95d9dc80b6771027daf545c621611fcb01854455ac2d44;

    // The values the pins carried before Step 3 was run. They are listed again so
    // the guard below can detect that they were never replaced -- a
    // `!= bytes32(0)` check cannot, because the placeholders are non-zero by
    // construction.
    bytes32 constant PLACEHOLDER_A = 0x00000000000000000000000000000000000000000000000000000000deadbe01;
    bytes32 constant PLACEHOLDER_B = 0x00000000000000000000000000000000000000000000000000000000deadbe02;
    bytes32 constant PLACEHOLDER_C = 0x00000000000000000000000000000000000000000000000000000000deadbe03;

    function _leaf(address op, uint256 nBytes, uint256 amt) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(DOMAIN, op, EPOCH, nBytes, amt))));
    }

    function _sortedPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(bytes.concat(a, b)) : keccak256(bytes.concat(b, a));
    }

    /// Mutations this detects: the domain word dropped from the encode on either
    /// side; abi.encode argument order changed; the double hash reduced to one.
    function test_rustProxyLeafMatchesSolidity() public pure {
        assertEq(_leaf(OP_A, BYTES_A, AMT_A), LEAF_A, "leaf A");
        assertEq(_leaf(OP_B, BYTES_B, AMT_B), LEAF_B, "leaf B");
        assertEq(_leaf(OP_A, BYTES_C, AMT_C), LEAF_C, "leaf C");
    }

    /// The pinned root, and that it is a root an OpenZeppelin verifier accepts.
    ///
    /// A leaf pin alone would stay green against a tree that pairs unsorted or
    /// concatenates in insertion order, and every proof the daemon produced would
    /// still be refused on chain.
    ///
    /// Mutations this detects: unsorted pairing in the Rust tree; the odd-node
    /// carry replaced by self-pairing; a proof emitted top-down.
    function test_rustProxyTwoLeafRootMatchesOz() public pure {
        assertEq(_sortedPair(LEAF_A, LEAF_B), TWO_LEAF_ROOT, "two-leaf root");

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = LEAF_B;
        assertTrue(MerkleProof.verify(proof, TWO_LEAF_ROOT, LEAF_A), "OZ verify A");
        proof[0] = LEAF_A;
        assertTrue(MerkleProof.verify(proof, TWO_LEAF_ROOT, LEAF_B), "OZ verify B");

        // Negative control: the verifier is not accepting everything. Without
        // this, a stubbed-out verify would satisfy both assertions above.
        proof[0] = LEAF_C;
        assertFalse(MerkleProof.verify(proof, TWO_LEAF_ROOT, LEAF_A), "OZ verify must refuse a wrong sibling");
    }

    /// Mutations this detects: the fetch leaf losing its domain, which would let
    /// a fetch-network proof settle through the MINTING EpochSettlement contract.
    function test_proxyLeafIsNotAnEpochSettlementLeaf() public pure {
        bytes32 epochStyle = keccak256(bytes.concat(keccak256(abi.encode(OP_A, AMT_A))));
        assertTrue(_leaf(OP_A, BYTES_A, AMT_A) != epochStyle, "proxy leaf collides with the compute leaf");

        // Domain separation is a property of the encoding, not of one lucky
        // vector. The same numeric inputs, every pinned pair.
        assertTrue(_leaf(OP_B, BYTES_B, AMT_B) != keccak256(bytes.concat(keccak256(abi.encode(OP_B, AMT_B)))));
        assertTrue(_leaf(OP_A, BYTES_C, AMT_C) != keccak256(bytes.concat(keccak256(abi.encode(OP_A, AMT_C)))));

        // And in the other direction: the compute preimage is 2 words, the fetch
        // preimage is 5, so no fetch leaf is reachable from a 2-word encode.
        assertEq(abi.encode(OP_A, AMT_A).length, 64);
        assertEq(abi.encode(DOMAIN, OP_A, EPOCH, BYTES_A, AMT_A).length, 160);
    }

    /// No pin may ship unfilled.
    ///
    /// A `!= bytes32(0)` guard cannot detect these placeholders, because they are
    /// non-zero by construction. This compares against the placeholder values
    /// themselves, so the only way to make it green is to run Step 3.
    function test_no_proxy_pin_is_unfilled() public pure {
        assertTrue(LEAF_A != bytes32(0) && LEAF_B != bytes32(0) && LEAF_C != bytes32(0));
        assertTrue(LEAF_A != PLACEHOLDER_A, "LEAF_A is still the placeholder; run Step 3");
        assertTrue(LEAF_B != PLACEHOLDER_B, "LEAF_B is still the placeholder; run Step 3");
        assertTrue(LEAF_C != PLACEHOLDER_C, "LEAF_C is still the placeholder; run Step 3");
        assertTrue(TWO_LEAF_ROOT != bytes32(0));
        assertTrue(LEAF_A != LEAF_B && LEAF_B != LEAF_C && LEAF_A != LEAF_C, "pins are not distinct");
    }

    /// The domain word this test hashes against must be the one the DEPLOYED
    /// contract uses, or parity is asserted between a local constant and itself.
    ///
    /// Mutations this detects: the contract's PROXY_LEAF_DOMAIN string edited
    /// without regenerating the Rust pins.
    function test_domain_constant_matches_the_deployed_contract() public {
        ProxyRevenueSettlement pool = _deployMinimal();
        assertEq(pool.PROXY_LEAF_DOMAIN(), DOMAIN, "the deployed domain has drifted from this pin");
        assertEq(DOMAIN, keccak256("GOAT_PROXY_REVENUE_LEAF_V1"));
    }

    /// The sample epoch every pin uses must be inside the space the deployed
    /// contract accepts, or the vectors pin an encoding no claim can ever reach.
    ///
    /// Mutations this detects: PROXY_EPOCH_BASE or the ceiling moved on either
    /// side of the language boundary.
    function test_pinned_epoch_lies_inside_the_deployed_proxy_epoch_space() public {
        ProxyRevenueSettlement pool = _deployMinimal();
        assertEq(pool.PROXY_EPOCH_BASE(), 8_000_000_000_000, "base drifted");
        assertEq(pool.PROXY_EPOCH_CEILING(), 9_000_000_000_000, "ceiling drifted");
        assertTrue(EPOCH >= pool.PROXY_EPOCH_BASE() && EPOCH < pool.PROXY_EPOCH_CEILING());
    }

    /// A real instance, wired only well enough to read a constant back off chain.
    function _deployMinimal() internal returns (ProxyRevenueSettlement) {
        address any = address(uint160(0xA11CE));
        return new ProxyRevenueSettlement(
            ProxyRevenueSettlement.Config({
                safe: any,
                goat: any,
                registry: any,
                treasury: any,
                attestorSafe: any,
                reserveSink: any,
                funder: any,
                publisher: any,
                gateway: any,
                usdtTreasury: any,
                resolver: any,
                watcher: any,
                challengeWindow: 6 hours,
                claimWindow: 30 days,
                resolveWindow: 7 days,
                proposerBond: 0.05 ether,
                challengerBond: 0.05 ether,
                referenceRateUsdtPerGoat: 1e6
            })
        );
    }
}
