// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";

contract WorkerBindingTest is Test {
    WorkerBinding binding;
    address alice;
    uint256 alicePk;
    address bob = makeAddr("bob");
    address relayer = makeAddr("relayer");

    function setUp() public {
        binding = new WorkerBinding();
        (alice, alicePk) = makeAddrAndKey("alice");
    }

    function test_bind_ok() public {
        vm.prank(alice);
        binding.bind("GOAT-alice");
        assertTrue(binding.bound(alice));
        assertEq(binding.usernameOf(alice), "GOAT-alice");
        assertEq(binding.walletOfNameHash(binding.nameHash("GOAT-alice")), alice);
    }

    function test_bind_setOnce() public {
        vm.prank(alice);
        binding.bind("GOAT-alice");
        vm.prank(alice);
        vm.expectRevert(WorkerBinding.AlreadyBound.selector);
        binding.bind("GOAT-alice2");
    }

    function test_bind_uniqueness() public {
        vm.prank(alice);
        binding.bind("GOAT-alice");
        vm.prank(bob);
        vm.expectRevert(WorkerBinding.NameTaken.selector);
        binding.bind("GOAT-alice");
    }

    function test_bind_prefixRequired() public {
        vm.prank(alice);
        vm.expectRevert(WorkerBinding.BadUsername.selector);
        binding.bind("alice");
        vm.prank(alice);
        vm.expectRevert(WorkerBinding.BadUsername.selector);
        binding.bind("GOAT-");
    }

    function test_bind_emits() public {
        vm.prank(alice);
        vm.expectEmit(true, false, false, true);
        emit WorkerBinding.Bound(alice, "GOAT-alice");
        binding.bind("GOAT-alice");
    }

    /// Relayer pays gas; wallet is recovered from worker signature — NOT msg.sender.
    function test_bindWithSignature_relayerDoesNotHijack() public {
        string memory username = "GOAT-alice";
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = binding.nonces(alice);

        bytes32 structHash = keccak256(
            abi.encode(
                binding.BIND_TYPEHASH(),
                alice,
                keccak256(bytes(username)),
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", binding.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Relayer submits — if code used msg.sender, binding would go to `relayer`.
        vm.prank(relayer);
        binding.bindWithSignature(alice, username, deadline, sig);

        assertTrue(binding.bound(alice));
        assertFalse(binding.bound(relayer));
        assertEq(binding.usernameOf(alice), username);
        assertEq(binding.walletOfNameHash(binding.nameHash(username)), alice);
        assertEq(binding.nonces(alice), 1);
    }

    function test_bindWithSignature_badSignerReverts() public {
        string memory username = "GOAT-alice";
        uint256 deadline = block.timestamp + 1 hours;
        // Sign with bob's key but claim alice's wallet
        (, uint256 bobPk) = makeAddrAndKey("bobSigner");
        bytes32 structHash = keccak256(
            abi.encode(
                binding.BIND_TYPEHASH(),
                alice,
                keccak256(bytes(username)),
                binding.nonces(alice),
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", binding.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bobPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(relayer);
        vm.expectRevert(WorkerBinding.BadSignature.selector);
        binding.bindWithSignature(alice, username, deadline, sig);
    }

    function test_bindWithSignature_expiredReverts() public {
        string memory username = "GOAT-alice";
        uint256 deadline = block.timestamp - 1;
        bytes32 structHash = keccak256(
            abi.encode(
                binding.BIND_TYPEHASH(),
                alice,
                keccak256(bytes(username)),
                binding.nonces(alice),
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", binding.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(WorkerBinding.ExpiredSignature.selector);
        binding.bindWithSignature(alice, username, deadline, sig);
    }

    function test_bindWithSignature_replayReverts() public {
        string memory username = "GOAT-alice";
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                binding.BIND_TYPEHASH(),
                alice,
                keccak256(bytes(username)),
                binding.nonces(alice),
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", binding.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        binding.bindWithSignature(alice, username, deadline, sig);

        // Same sig again: nonce was already consumed → recovery fails (BadSignature).
        // That still prevents replay. A second bind for the same wallet with a fresh
        // signature would hit AlreadyBound.
        vm.expectRevert(WorkerBinding.BadSignature.selector);
        binding.bindWithSignature(alice, username, deadline, sig);

        // Fresh signature, same wallet → AlreadyBound (set-once).
        uint256 deadline2 = block.timestamp + 2 hours;
        bytes32 structHash2 = keccak256(
            abi.encode(
                binding.BIND_TYPEHASH(),
                alice,
                keccak256(bytes(username)),
                binding.nonces(alice),
                deadline2
            )
        );
        bytes32 digest2 = keccak256(abi.encodePacked("\x19\x01", binding.DOMAIN_SEPARATOR(), structHash2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(alicePk, digest2);
        bytes memory sig2 = abi.encodePacked(r2, s2, v2);
        vm.expectRevert(WorkerBinding.AlreadyBound.selector);
        binding.bindWithSignature(alice, username, deadline2, sig2);
    }
}
