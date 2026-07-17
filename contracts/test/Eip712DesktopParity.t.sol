// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";

/// Cross-stack EIP-712 parity (consultant 2026-07-15).
///
/// Pinned digests + signatures are produced by **viem** (`hashTypedData` /
/// `signTypedData`) using the same domain names/versions/types as
/// `desktop/src/chain/attribution.js`. Forge recomputes the EIP-712 digest with
/// the standard domain separator formula and recovers the signer — proving the
/// React/viem encoding is the one Solidity will accept.
///
/// Vectors regenerated with (from repo desktop/):
///   node --input-type=module -e '... hashTypedData(buildBindTypedData(...))'
/// See docs/reports/2026-07-15-session-report-eip712-relayer-hardening.md
contract Eip712DesktopParityTest is Test {
    using ECDSA for bytes32;

    // Anvil account #0 (TEST KEY ONLY — never fund on mainnet for real value).
    uint256 constant ANVIL0_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address constant ANVIL0 = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    uint256 constant CHAIN_ID = 31337;
    address constant VERIFY_BIND = 0x1111111111111111111111111111111111111111;
    address constant VERIFY_ENROLL = 0x2222222222222222222222222222222222222222;
    string constant USERNAME = "GOAT-alice";
    uint256 constant NONCE = 0;
    uint256 constant DEADLINE = 2_000_000_000;

    // Pinned from viem hashTypedData / signTypedData (attribution.js domain/types).
    bytes32 constant BIND_DIGEST =
        0x6760436048cb4918b0cd773e2c2db5f6bb28c3b8fb7cf34f215da680806cdfa2;
    bytes32 constant ENROLL_DIGEST =
        0xc815623fc9a5e16ee135627955085cd554d7a678a970dd8e97297b17f629c1e7;
    bytes constant BIND_SIG =
        hex"5519983078728025bbcbdd0a213cf4a1545bfa71a48e86552a9c2be2802927f343e7b82e6a3a974e6dff2139e28e6d9eb270c59cd3dbf45c7ff2a72cb16dd7a61c";
    bytes constant ENROLL_SIG =
        hex"1310f358af0800ba1551d77e5b962a95b1cb1460b49075632ae201fc5f8108a8513d78e9c625cd0cfc02b70b8b0c4e37fec3f20f5e017ef72bd2913779dac9f91c";

    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 constant BIND_TYPEHASH =
        keccak256("Bind(address wallet,string username,uint256 nonce,uint256 deadline)");
    bytes32 constant ENROLL_TYPEHASH =
        keccak256("Enroll(address wallet,uint256 nonce,uint256 deadline)");

    function _domainSeparator(string memory name, string memory version, uint256 chainId, address verifying)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
    }

    function _bindDigest(
        address verifying,
        address wallet,
        string memory username,
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (bytes32) {
        bytes32 domain = _domainSeparator("GoatWorkerBinding", "1", CHAIN_ID, verifying);
        bytes32 structHash = keccak256(
            abi.encode(BIND_TYPEHASH, wallet, keccak256(bytes(username)), nonce, deadline)
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _enrollDigest(address verifying, address wallet, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        bytes32 domain = _domainSeparator("GoatEnrollmentRegistry", "1", CHAIN_ID, verifying);
        bytes32 structHash = keccak256(abi.encode(ENROLL_TYPEHASH, wallet, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    /// viem digest == Solidity EIP-712 encoding for Bind.
    function test_viemBindDigest_matchesSolidityEncoding() public pure {
        bytes32 d = _bindDigest(VERIFY_BIND, ANVIL0, USERNAME, NONCE, DEADLINE);
        assertEq(d, BIND_DIGEST, "Bind digest must match viem hashTypedData");
    }

    /// viem digest == Solidity EIP-712 encoding for Enroll.
    function test_viemEnrollDigest_matchesSolidityEncoding() public pure {
        bytes32 d = _enrollDigest(VERIFY_ENROLL, ANVIL0, NONCE, DEADLINE);
        assertEq(d, ENROLL_DIGEST, "Enroll digest must match viem hashTypedData");
    }

    /// viem signature recovers the worker (not the relayer).
    function test_viemBindSignature_recoversWorker() public pure {
        address recovered = ECDSA.recover(BIND_DIGEST, BIND_SIG);
        assertEq(recovered, ANVIL0, "Bind sig must recover anvil#0 / worker");
    }

    function test_viemEnrollSignature_recoversWorker() public pure {
        address recovered = ECDSA.recover(ENROLL_DIGEST, ENROLL_SIG);
        assertEq(recovered, ANVIL0, "Enroll sig must recover anvil#0 / worker");
    }

    /// Live contracts use the same TYPEHASH + domain name/version; DOMAIN_SEPARATOR
    /// matches the pure formula for (name, version, chainid, address(this)).
    function test_deployedWorkerBinding_domainMatchesFormula() public {
        WorkerBinding binding = new WorkerBinding();
        assertEq(binding.BIND_TYPEHASH(), BIND_TYPEHASH);
        bytes32 expected = _domainSeparator(
            "GoatWorkerBinding", "1", block.chainid, address(binding)
        );
        assertEq(binding.DOMAIN_SEPARATOR(), expected);
    }

    function test_deployedEnrollmentRegistry_domainMatchesFormula() public {
        EnrollmentRegistry reg = new EnrollmentRegistry(makeAddr("safe"));
        assertEq(reg.ENROLL_TYPEHASH(), ENROLL_TYPEHASH);
        bytes32 expected = _domainSeparator(
            "GoatEnrollmentRegistry", "1", block.chainid, address(reg)
        );
        assertEq(reg.DOMAIN_SEPARATOR(), expected);
    }

    /// End-to-end: signature over the *deployed* domain (vm.sign) accepted by bindWithSignature.
    /// Complements viem-pinned vectors: proves contract path with correct domain fields.
    function test_bindWithSignature_acceptsDigestCompatibleWithDesktopTypes() public {
        WorkerBinding binding = new WorkerBinding();
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = binding.nonces(ANVIL0);
        bytes32 structHash = keccak256(
            abi.encode(binding.BIND_TYPEHASH(), ANVIL0, keccak256(bytes(USERNAME)), nonce, deadline)
        );
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", binding.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ANVIL0_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        address relayer = makeAddr("relayer");
        vm.prank(relayer);
        binding.bindWithSignature(ANVIL0, USERNAME, deadline, sig);

        assertTrue(binding.bound(ANVIL0));
        assertEq(binding.usernameOf(ANVIL0), USERNAME);
        assertFalse(binding.bound(relayer));
    }

    function test_enrollSelfWithSignature_acceptsDigestCompatibleWithDesktopTypes() public {
        EnrollmentRegistry reg = new EnrollmentRegistry(makeAddr("safe"));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = reg.nonces(ANVIL0);
        bytes32 structHash =
            keccak256(abi.encode(reg.ENROLL_TYPEHASH(), ANVIL0, nonce, deadline));
        bytes32 digest =
            keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ANVIL0_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        address relayer = makeAddr("relayer");
        vm.prank(relayer);
        reg.enrollSelfWithSignature(ANVIL0, deadline, sig);

        assertTrue(reg.enrolled(ANVIL0));
        assertFalse(reg.enrolled(relayer));
    }
}
