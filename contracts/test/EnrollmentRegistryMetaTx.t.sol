// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";

contract EnrollmentRegistryMetaTxTest is Test {
    EnrollmentRegistry reg;
    address safe = makeAddr("safe");
    address alice;
    uint256 alicePk;
    address relayer = makeAddr("relayer");

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        (alice, alicePk) = makeAddrAndKey("alice");
    }

    function test_enrollSelf_ok() public {
        vm.prank(alice);
        reg.enrollSelf();
        assertTrue(reg.enrolled(alice));
    }

    function test_enrollSelfWithSignature_relayerDoesNotHijack() public {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = reg.nonces(alice);
        bytes32 structHash =
            keccak256(abi.encode(reg.ENROLL_TYPEHASH(), alice, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        reg.enrollSelfWithSignature(alice, deadline, sig);

        assertTrue(reg.enrolled(alice));
        assertFalse(reg.enrolled(relayer));
        assertEq(reg.nonces(alice), 1);
    }

    function test_enrollSelfWithSignature_blacklistedReverts() public {
        vm.prank(safe);
        reg.setBlacklisted(alice, true);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(reg.ENROLL_TYPEHASH(), alice, reg.nonces(alice), deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        vm.expectRevert(EnrollmentRegistry.Blacklisted.selector);
        reg.enrollSelfWithSignature(alice, deadline, sig);
    }

    function test_enrollSelfWithSignature_expiredReverts() public {
        uint256 deadline = block.timestamp - 1;
        bytes32 structHash = keccak256(
            abi.encode(reg.ENROLL_TYPEHASH(), alice, reg.nonces(alice), deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(EnrollmentRegistry.ExpiredSignature.selector);
        reg.enrollSelfWithSignature(alice, deadline, sig);
    }
}
