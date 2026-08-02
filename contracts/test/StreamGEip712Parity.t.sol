// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StreamGTypes} from "../src/StreamGTypes.sol";
import {GoatRelayGateway} from "../src/GoatRelayGateway.sol";
import {IEnrollmentRegistryV1} from "../src/interfaces/IEnrollmentRegistryV1.sol";
import {IEIP3009} from "../src/interfaces/IEIP3009.sol";

/// Exposes `GoatRelayGateway`'s **real** internal EIP-712 hashing so tests can
/// assert against the production encoding rather than a re-implementation.
///
/// Why this exists: `StreamGEip712ParityTest._feeQuoteDigest` (below) rebuilds
/// the struct hash locally with its own `abi.encode`. That pins the fixture
/// against *this file*, not against the contract — if `_feeQuoteStructHash`
/// ever reordered a field, the local helper would reorder nothing and the test
/// would stay green. Same self-referential defect the Rust-side review caught
/// as finding I4. These two must be cross-checked against each other.
contract GatewayHashHarness is GoatRelayGateway {
    constructor(address a, address b, address c, address d, address e, address f) GoatRelayGateway(a, b, c, d, e, f) {}

    function exposedFeeQuoteStructHash(StreamGTypes.FeeQuote calldata q) external pure returns (bytes32) {
        return _feeQuoteStructHash(q);
    }

    function exposedHashTypedDataV4(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }

    /// Task 6b independent-verifier follow-up (Task 4): brief §4.5 owed a
    /// Solidity-side proof of the `SponsorEnrollment` digest (check 18's
    /// sibling — `GoatRelayGateway.sol:400-402`, check 20). Wave B's
    /// typehash/struct-hash/digest pins were `cast`-derived on the Rust side
    /// only. `_sponsorEnrollmentStructHash` is `internal`, so extend this
    /// harness the same way `exposedFeeQuoteStructHash` already does.
    function exposedSponsorEnrollmentStructHash(StreamGTypes.SponsorEnrollment calldata intent)
        external
        pure
        returns (bytes32)
    {
        return _sponsorEnrollmentStructHash(intent);
    }
}

/// Stream G EIP-712 type/hash freeze for G1.
/// Fixture digests in fixtures/stream_g_eip712_vectors.json are computed by the
/// same domain-separator formula used in Eip712DesktopParity.t.sol.
contract StreamGEip712ParityTest is Test {
    uint256 constant CHAIN_ID = 31337;
    address constant VERIFY_GATEWAY = 0x3333333333333333333333333333333333333333;

    bytes32 constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // Pinned from Solidity encoding of the fixture fields below (probe 2026-07-22).
    bytes32 constant FEE_QUOTE_DIGEST = 0xb82a7f8564a67b0225bf729dfcd86961ff34b3a583c7ecd7c38d1011c3881469;
    bytes32 constant FEE_QUOTE_TYPEHASH_PINNED = 0xeaeb044887c8cf8cd0fa7dcbfa981c25dd31ffebc55f4eca160b680c34ff4169;
    bytes32 constant ACTION_SPONSORED_ENROLLMENT_PINNED =
        0xbcd123c051cd9b628e040adc5b6509f0a172883d597875aa799b30bfe9a82807;
    bytes32 constant SPONSOR_ENROLLMENT_TYPEHASH_PINNED =
        0xaa3769f433b96287c3b0838abbc6b35619375fea0e81929c58cf672804b9e885;
    bytes32 constant SPONSOR_ENROLLMENT_CORE_TYPEHASH_PINNED =
        0x1eed3561f8deb1be9863b6ba6959db364a4910bd36991fb749cb4ae27e1246f4;
    bytes32 constant LINK_SECONDARY_TYPEHASH_PINNED =
        0xd13c2b44c281e3e64f71fefdd22c0981a18181362d0596732c5432c20c0c275b;
    bytes32 constant FEE_TOKEN_CONFIG_TYPEHASH_PINNED =
        0xdf3f4881a773320188104db0a63dab7043eb60cac6c8e7eea34993ccf6e77b36;

    // Residential-proxy settlement action types (2026-07-31). Derived, not
    // typed: `cast keccak "GOAT_STREAM_G_PROXY_CLAIM_V1"` and so on, then
    // re-derived independently with contracts/test/keccak256.mjs. The Rust
    // twin is `quotes.rs::tests::action_type_strings_pinned`, which pins the
    // same three digests against `ActionType::digest()`.
    bytes32 constant ACTION_PROXY_CLAIM_PINNED = 0x03791b0650b89c9f3b82a61b43fdd4129842b5036666c3e071af74325dc17ed9;
    bytes32 constant ACTION_PROXY_PROPOSE_BATCH_PINNED =
        0x5e1dabd4d4b0e517013f1c8e075dab1c1f6bc95ee81ff1afbfdf2b1907a73cb7;
    bytes32 constant ACTION_PROXY_CHALLENGE_BATCH_PINNED =
        0x274e67d1bddbe9e93b190fdf58c0e6ab56865c58974ce3b4bb37f5482f5d259f;

    function test_authorization_mode_ordinals_are_not_capability_bits() public pure {
        assertEq(uint8(StreamGTypes.AuthorizationMode.NONE), 0);
        assertEq(uint8(StreamGTypes.AuthorizationMode.EIP2612), 1);
        assertEq(uint8(StreamGTypes.AuthorizationMode.EIP3009), 2);
        assertEq(uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE), 3);

        assertEq(StreamGTypes.CAP_EIP2612, 1 << 0);
        assertEq(StreamGTypes.CAP_EIP3009, 1 << 1);
        assertEq(StreamGTypes.CAP_PRIOR_ALLOWANCE, 1 << 2);
        assertEq(StreamGTypes.CAP_SELL_SPLIT, 1 << 3);

        // Capability bit 3 must not equal mode ordinal 3.
        assertTrue(StreamGTypes.CAP_SELL_SPLIT != uint256(uint8(StreamGTypes.AuthorizationMode.PRIOR_ALLOWANCE)));
    }

    function test_action_type_constants_match_design() public pure {
        assertEq(StreamGTypes.ACTION_SPONSORED_ENROLLMENT, ACTION_SPONSORED_ENROLLMENT_PINNED);
        assertEq(StreamGTypes.ACTION_SPONSORED_ENROLLMENT, keccak256("GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1"));
        assertEq(StreamGTypes.ACTION_SPONSORED_SELL, keccak256("GOAT_STREAM_G_SPONSORED_SELL_V1"));
        assertEq(StreamGTypes.ACTION_GOAT_TRANSFER, keccak256("GOAT_STREAM_G_GOAT_TRANSFER_V1"));
        assertEq(StreamGTypes.ACTION_USDT_TRANSFER, keccak256("GOAT_STREAM_G_USDT_TRANSFER_V1"));

        assertEq(StreamGTypes.ACTION_PROXY_CLAIM, ACTION_PROXY_CLAIM_PINNED);
        assertEq(StreamGTypes.ACTION_PROXY_CLAIM, keccak256("GOAT_STREAM_G_PROXY_CLAIM_V1"));
        assertEq(StreamGTypes.ACTION_PROXY_PROPOSE_BATCH, ACTION_PROXY_PROPOSE_BATCH_PINNED);
        assertEq(StreamGTypes.ACTION_PROXY_PROPOSE_BATCH, keccak256("GOAT_STREAM_G_PROXY_PROPOSE_BATCH_V1"));
        assertEq(StreamGTypes.ACTION_PROXY_CHALLENGE_BATCH, ACTION_PROXY_CHALLENGE_BATCH_PINNED);
        assertEq(StreamGTypes.ACTION_PROXY_CHALLENGE_BATCH, keccak256("GOAT_STREAM_G_PROXY_CHALLENGE_BATCH_V1"));
    }

    function test_primary_typehashes_match_canonical_strings() public pure {
        assertEq(StreamGTypes.FEE_QUOTE_TYPEHASH, FEE_QUOTE_TYPEHASH_PINNED);
        assertEq(StreamGTypes.SPONSOR_ENROLLMENT_TYPEHASH, SPONSOR_ENROLLMENT_TYPEHASH_PINNED);
        assertEq(StreamGTypes.SPONSOR_ENROLLMENT_CORE_TYPEHASH, SPONSOR_ENROLLMENT_CORE_TYPEHASH_PINNED);
        assertEq(StreamGTypes.LINK_SECONDARY_TYPEHASH, LINK_SECONDARY_TYPEHASH_PINNED);
        assertEq(StreamGTypes.FEE_TOKEN_CONFIG_TYPEHASH, FEE_TOKEN_CONFIG_TYPEHASH_PINNED);

        assertEq(
            StreamGTypes.FEE_QUOTE_TYPEHASH,
            keccak256(
                "FeeQuote(bytes32 quoteId,bytes32 actionType,bytes32 actionCoreHash,bytes32 deploymentManifestHash,bytes32 feeTokenConfigHash,bytes32 feeScheduleHash,address payer,address feeToken,uint256 feeAmount,address feeRecipient,uint48 validAfter,uint48 validUntil)"
            )
        );
        assertEq(
            StreamGTypes.LINK_SECONDARY_TYPEHASH,
            keccak256("LinkSecondary(address root,address secondary,uint256 nonce,uint48 deadline)")
        );
        assertEq(
            StreamGTypes.ROOT_AUTHORIZATION_TYPEHASH,
            keccak256(
                "RootAuthorization(address root,address secondary,bytes32 enrollDigest,bytes32 linkDigest,uint256 nonce,uint48 deadline)"
            )
        );
        assertEq(
            StreamGTypes.PRIOR_ALLOWANCE_AUTHORIZATION_TYPEHASH,
            keccak256(
                "PriorAllowanceAuthorization(bytes32 intentId,bytes32 actionType,address owner,address token,address spender,uint256 value,uint256 nonce,uint48 deadline)"
            )
        );
        assertEq(
            StreamGTypes.CONTROLLER_ROTATION_TYPEHASH,
            keccak256(
                "ControllerRotation(address root,address oldController,address newController,uint256 nonce,uint48 deadline)"
            )
        );
        assertEq(
            StreamGTypes.EIP2612_PERMIT_TYPEHASH,
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
        );
        assertEq(
            StreamGTypes.EIP3009_RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
            keccak256(
                "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
            )
        );
    }

    function _domainSeparator(string memory name, string memory version, uint256 chainId, address verifying)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying)
        );
    }

    function _feeQuoteDigest(StreamGTypes.FeeQuote memory q, address verifying) internal pure returns (bytes32) {
        bytes32 domain = _domainSeparator("GoatRelayGateway", "1", CHAIN_ID, verifying);
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.FEE_QUOTE_TYPEHASH,
                q.quoteId,
                q.actionType,
                q.actionCoreHash,
                q.deploymentManifestHash,
                q.feeTokenConfigHash,
                q.feeScheduleHash,
                q.payer,
                q.feeToken,
                q.feeAmount,
                q.feeRecipient,
                q.validAfter,
                q.validUntil
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _fixtureFeeQuote() internal pure returns (StreamGTypes.FeeQuote memory q) {
        q = StreamGTypes.FeeQuote({
            quoteId: bytes32(uint256(1)),
            actionType: keccak256("GOAT_STREAM_G_SPONSORED_ENROLLMENT_V1"),
            actionCoreHash: bytes32(uint256(2)),
            deploymentManifestHash: bytes32(uint256(3)),
            feeTokenConfigHash: bytes32(uint256(4)),
            feeScheduleHash: bytes32(uint256(5)),
            payer: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,
            feeToken: 0x00000000000000000000000000000000000000A1,
            feeAmount: 250_000,
            feeRecipient: 0x00000000000000000000000000000000000000B1,
            validAfter: 1_700_000_000,
            validUntil: 1_700_000_120
        });
    }

    function test_fee_quote_digest_matches_pinned_fixture() public pure {
        bytes32 digest = _feeQuoteDigest(_fixtureFeeQuote(), VERIFY_GATEWAY);
        assertEq(digest, FEE_QUOTE_DIGEST, "FeeQuote digest must match pinned fixture");
    }

    // ------------------------------------------------------------------
    // Cross-language parity with tools/goat-attestor (Stream G Task 6a/6b).
    //
    // The attestor signs every FeeQuote in Rust; the gateway verifies in
    // Solidity. `GoatRelayGateway.sol:394` binds an intent to the quote's
    // FULL EIP-712 digest (not `quoteId`), so any divergence in domain,
    // typehash, field order or word packing reverts every sponsored
    // enrollment with `InvalidQuote`.
    //
    // Fixture and expected values below are the ones pinned Rust-side in
    // `stream_g/quotes.rs::fee_quote_digest_regression_fixed_inputs`. Those
    // literals were derived with `cast keccak` independently of the Rust,
    // then re-derived a second time by an independent reviewer. Asserting
    // them here from the REAL contract internals closes the loop in both
    // directions.
    // ------------------------------------------------------------------

    uint256 constant RUST_CHAIN_ID = 31337;
    address constant RUST_VERIFYING_CONTRACT = 0x1010101010101010101010101010101010101010;

    bytes32 constant RUST_PINNED_DOMAIN_SEPARATOR = 0x5c9e2040dd5b30c28be6d5a4742785cf7a77e870d7ef411104dfe3aecd0eca60;
    bytes32 constant RUST_PINNED_STRUCT_HASH = 0x6cd18e6e3d505795b3c1f47735731eb67c0c8ce72a8dc1a4dcfd286580c2c9c4;
    bytes32 constant RUST_PINNED_DIGEST = 0x0ddf83131e514d4868ed12dc965bffa737c12504e949ae525cb5b8964ce28d4f;

    /// The exact `FeeQuote` the Rust regression test hashes.
    function _rustParityFeeQuote() internal pure returns (StreamGTypes.FeeQuote memory q) {
        q = StreamGTypes.FeeQuote({
            quoteId: bytes32(_repeat(0x01)),
            actionType: bytes32(_repeat(0x02)),
            actionCoreHash: bytes32(_repeat(0x03)),
            deploymentManifestHash: bytes32(_repeat(0x04)),
            feeTokenConfigHash: bytes32(_repeat(0x05)),
            feeScheduleHash: bytes32(_repeat(0x06)),
            payer: 0x0707070707070707070707070707070707070707,
            feeToken: 0x0808080808080808080808080808080808080808,
            feeAmount: 500_000,
            feeRecipient: 0x0909090909090909090909090909090909090909,
            validAfter: 2_000_000_000,
            validUntil: 2_000_000_300
        });
    }

    /// A 32-byte word with every byte set to `b` (mirrors Rust's `[0xNN; 32]`).
    function _repeat(uint8 b) internal pure returns (uint256 word) {
        for (uint256 i = 0; i < 32; i++) {
            word = (word << 8) | b;
        }
    }

    function _deployHarnessAt(address where) internal returns (GatewayHashHarness) {
        GatewayHashHarness impl = new GatewayHashHarness(
            address(0xA1), address(0xA2), address(0xA3), address(0xA4), address(0xA5), address(0xA6)
        );
        // Etch so `_hashTypedDataV4` sees `address(this) == where`. OpenZeppelin's
        // EIP712 caches the separator against the deploy address and rebuilds
        // whenever `address(this)` differs, so the etched copy recomputes the
        // domain for `where` rather than returning the cached one.
        vm.etch(where, address(impl).code);
        return GatewayHashHarness(where);
    }

    /// Hazard B: the attestor's Rust digest must equal what the gateway itself
    /// computes, over the same fixture. Mutation this detects: any field
    /// reorder or width change in `_feeQuoteStructHash`, or a domain
    /// name/version change in the `EIP712(...)` constructor argument.
    function test_fee_quote_digest_matches_rust_attestor_pin() public {
        GatewayHashHarness gw = _deployHarnessAt(RUST_VERIFYING_CONTRACT);
        StreamGTypes.FeeQuote memory q = _rustParityFeeQuote();

        assertEq(block.chainid, RUST_CHAIN_ID, "fixture assumes chainid 31337");

        bytes32 structHash = gw.exposedFeeQuoteStructHash(q);
        assertEq(structHash, RUST_PINNED_STRUCT_HASH, "struct hash diverged from the Rust attestor pin");

        bytes32 domain = gw.DOMAIN_SEPARATOR();
        assertEq(domain, RUST_PINNED_DOMAIN_SEPARATOR, "domain separator diverged from the Rust attestor pin");

        bytes32 digest = gw.exposedHashTypedDataV4(structHash);
        assertEq(digest, RUST_PINNED_DIGEST, "FeeQuote digest diverged from the Rust attestor pin");
    }

    /// This file's local `_feeQuoteDigest` re-implements the encoding. Prove it
    /// agrees with the contract, otherwise the older pinned-fixture test above
    /// is self-referential. Mutation this detects: a field reorder applied to
    /// `_feeQuoteStructHash` but not to the local helper (or vice versa).
    function test_local_helper_encoding_agrees_with_the_real_gateway() public {
        GatewayHashHarness gw = _deployHarnessAt(RUST_VERIFYING_CONTRACT);
        StreamGTypes.FeeQuote memory q = _rustParityFeeQuote();

        assertEq(
            _feeQuoteDigestAt(q, RUST_VERIFYING_CONTRACT),
            gw.exposedHashTypedDataV4(gw.exposedFeeQuoteStructHash(q)),
            "local test helper and GoatRelayGateway disagree on FeeQuote encoding"
        );
    }

    // ------------------------------------------------------------------
    // Task 6b independent-verifier follow-up (Task 4): SponsorEnrollment
    // digest — check 18's sibling (check 20, GoatRelayGateway.sol:400-402).
    //
    // Same domain as FeeQuote ("GoatRelayGateway"/"1"), so
    // RUST_PINNED_DOMAIN_SEPARATOR is reused; the struct hash and digest
    // below are new pins over the exact fixture the Rust regression test
    // `preflight::tests::sponsor_enrollment_digest_regression_fixed_inputs`
    // hashes (`tools/goat-attestor/src/stream_g/preflight.rs`).
    // ------------------------------------------------------------------

    bytes32 constant RUST_SPONSOR_ENROLLMENT_STRUCT_HASH =
        0xabe0223d45eaf26007f8617d87730e7bc3888b68ef91fbe90b8c4cf4e3390c45;
    bytes32 constant RUST_SPONSOR_ENROLLMENT_DIGEST =
        0xfb47f0876c6437931605bf198175a8c81ea5216dbe7e37bdf112d54d0bda8403;

    /// The exact `SponsorEnrollment` the Rust regression test hashes.
    function _rustParitySponsorEnrollment() internal pure returns (StreamGTypes.SponsorEnrollment memory i) {
        i = StreamGTypes.SponsorEnrollment({
            intentId: bytes32(_repeat(0x01)),
            deploymentManifestHash: bytes32(_repeat(0x02)),
            feeTokenConfigHash: bytes32(_repeat(0x03)),
            root: 0x0404040404040404040404040404040404040404,
            controller: 0x0505050505050505050505050505050505050505,
            controllerEpoch: 7,
            secondary: 0x0606060606060606060606060606060606060606,
            enrollDigest: bytes32(_repeat(0x08)),
            linkDigest: bytes32(_repeat(0x09)),
            rootAuthorizationDigest: bytes32(0),
            feeToken: 0x0A0A0a0a0a0a0a0A0a0a0A0a0A0A0A0a0a0a0a0a,
            feeAuthorizationMode: 1,
            feeAuthorizationDigest: bytes32(_repeat(0x0b)),
            maxFee: 1_000_000,
            feeQuoteHash: bytes32(_repeat(0x0c)),
            nonce: 3,
            deadline: 2_000_000_100
        });
    }

    /// Hazard B / Task 4: the attestor's Rust `SponsorEnrollment` digest must
    /// equal what the gateway itself computes, over the same fixture.
    /// Mutation this detects: any field reorder or width change in
    /// `_sponsorEnrollmentStructHash`, or a drift between the two languages'
    /// `SPONSOR_ENROLLMENT_TYPEHASH` copies.
    function test_sponsor_enrollment_digest_matches_rust_attestor_pin() public {
        GatewayHashHarness gw = _deployHarnessAt(RUST_VERIFYING_CONTRACT);
        StreamGTypes.SponsorEnrollment memory i = _rustParitySponsorEnrollment();

        assertEq(block.chainid, RUST_CHAIN_ID, "fixture assumes chainid 31337");

        bytes32 structHash = gw.exposedSponsorEnrollmentStructHash(i);
        assertEq(
            structHash,
            RUST_SPONSOR_ENROLLMENT_STRUCT_HASH,
            "SponsorEnrollment struct hash diverged from the Rust attestor pin"
        );

        // Same domain as FeeQuote's — SponsorEnrollment is signed under
        // GoatRelayGateway's own EIP712("GoatRelayGateway","1") domain too
        // (models::FEE_QUOTE_DOMAIN_NAME/VERSION, reused by
        // `sponsor_enrollment_digest` Rust-side), so the same domain
        // separator applies without any new pin.
        bytes32 domain = gw.DOMAIN_SEPARATOR();
        assertEq(
            domain, RUST_PINNED_DOMAIN_SEPARATOR, "domain separator diverged (should be identical to FeeQuote's domain)"
        );

        bytes32 digest = gw.exposedHashTypedDataV4(structHash);
        assertEq(digest, RUST_SPONSOR_ENROLLMENT_DIGEST, "SponsorEnrollment digest diverged from the Rust attestor pin");
    }

    /// Same as `_feeQuoteDigest` but chain-id explicit, so the parity fixture
    /// is not tied to the older `CHAIN_ID` constant.
    function _feeQuoteDigestAt(StreamGTypes.FeeQuote memory q, address verifying) internal view returns (bytes32) {
        bytes32 domain = _domainSeparator("GoatRelayGateway", "1", block.chainid, verifying);
        bytes32 structHash = keccak256(
            abi.encode(
                StreamGTypes.FEE_QUOTE_TYPEHASH,
                q.quoteId,
                q.actionType,
                q.actionCoreHash,
                q.deploymentManifestHash,
                q.feeTokenConfigHash,
                q.feeScheduleHash,
                q.payer,
                q.feeToken,
                q.feeAmount,
                q.feeRecipient,
                q.validAfter,
                q.validUntil
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function test_frozen_interfaces_selectors_are_stable() public pure {
        // Compile-time presence + selector freeze for later gateway wiring.
        assertEq(
            IEnrollmentRegistryV1.enrollSelfWithSignature.selector,
            bytes4(keccak256("enrollSelfWithSignature(address,uint256,bytes)"))
        );
        assertEq(IEnrollmentRegistryV1.nonces.selector, bytes4(keccak256("nonces(address)")));
        assertEq(
            IEIP3009.receiveWithAuthorization.selector,
            bytes4(
                keccak256(
                    "receiveWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"
                )
            )
        );
        assertEq(IEIP3009.authorizationState.selector, bytes4(keccak256("authorizationState(address,bytes32)")));
    }
}
