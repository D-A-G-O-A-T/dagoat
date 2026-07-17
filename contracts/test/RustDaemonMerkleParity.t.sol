// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {EnrollmentRegistry} from "../src/EnrollmentRegistry.sol";
import {GoatCoin} from "../src/GoatCoin.sol";
import {HoldbackEscrow} from "../src/HoldbackEscrow.sol";
import {EpochSettlement} from "../src/EpochSettlement.sol";
import {FounderResolver} from "../src/FounderResolver.sol";
import {WorkerBinding} from "../src/WorkerBinding.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";

/// Cross-language Merkle parity: constants pinned from
/// `tools/goat-attestor` (`cargo test merkle::tests::pinned_solidity_cross_check_vectors`).
///
/// If these fail, Rust `abi_encode` / leaf hashing has drifted from Solidity
/// `keccak256(bytes.concat(keccak256(abi.encode(worker, score))))` and all
/// daemon-produced proofs will `BadProof` on-chain.
contract RustDaemonMerkleParityTest is Test {
    EnrollmentRegistry reg;
    GoatCoin goat;
    HoldbackEscrow escrow;
    EpochSettlement settle;
    FounderResolver resolver;
    WorkerBinding binding;

    address safe = makeAddr("safe");
    address reserve = makeAddr("reserve");
    address founder = makeAddr("founder");
    address watcher = makeAddr("watcher");
    address proposer = makeAddr("proposer");

    /// Fixed worker matching Rust `addr(0xA1)` = address(uint160(0xA1)).
    address workerA1 = address(uint160(0xA1));

    uint16 constant HB_BPS = 500;
    uint64 constant BACKSTOP = 7 days;
    uint256 constant RATE = uint256(1e18) / 24000;
    uint256 constant CAP_PER_DAY = 67e18;
    uint64 constant WINDOW = 12 hours;
    uint256 constant PBOND = 0.01 ether;
    uint256 constant CBOND = 0.01 ether;

    // ---- pinned from goat-attestor Rust ----
    bytes32 constant LEAF_A1_2_4M =
        0x735d83c0039ed03f4cca68b065b6e55d6c07c6ac7eb5ad442617b505ea9a90ad;
    bytes32 constant LEAF_B2_600K =
        0x78dafc39810f27c2d406a8f9fd8f9b72d732a084e94ccbbcec98f55dca76c584;
    bytes32 constant TWO_LEAF_ROOT =
        0x2e0d8025677441483e6272a58d9330425259dd82b8dea14744ca3e1517f2c269;
    bytes32 constant LEAF_A1_100K =
        0xf57f8dacf75442d4a5bf6d6e25e75e5fa87abc1a7b255f00b4456e922bdcb413;

    function setUp() public {
        reg = new EnrollmentRegistry(safe);
        goat = new GoatCoin("GoatCoin", "GOAT", safe, reg);
        escrow = new HoldbackEscrow(safe, goat, reserve);
        binding = new WorkerBinding();
        settle = new EpochSettlement(
            safe,
            goat,
            escrow,
            reg,
            binding,
            HB_BPS,
            BACKSTOP,
            RATE,
            CAP_PER_DAY,
            WINDOW,
            PBOND,
            CBOND,
            address(0),
            watcher
        );
        resolver = new FounderResolver(founder, address(settle));
        vm.startPrank(safe);
        escrow.setVault(address(settle));
        goat.setMinter(address(settle), true);
        reg.setSystemAddress(address(escrow), true);
        reg.setSystemAddress(address(settle), true);
        reg.setSystemAddress(reserve, true);
        settle.setResolver(address(resolver));
        vm.stopPrank();
        vm.deal(proposer, 1 ether);

        // Enroll + bind the fixed A1 worker under a valid GOAT- username.
        vm.prank(workerA1);
        reg.enrollSelf();
        vm.prank(workerA1);
        binding.bind("GOAT-a1");
    }

    function _solLeaf(address worker, uint256 score) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(worker, score))));
    }

    function _sortedPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b
            ? keccak256(bytes.concat(a, b))
            : keccak256(bytes.concat(b, a));
    }

    function test_rustLeafMatchesSolidity_doubleHashAbiEncode() public pure {
        address a1 = address(uint160(0xA1));
        address b2 = address(uint160(0xB2));
        assertEq(_solLeaf(a1, 2_400_000), LEAF_A1_2_4M, "leaf A1@2.4M");
        assertEq(_solLeaf(b2, 600_000), LEAF_B2_600K, "leaf B2@600k");
        assertEq(_solLeaf(a1, 100_000), LEAF_A1_100K, "leaf A1@100k");
    }

    function test_rustTwoLeafRootAndProof_matchesOz() public pure {
        bytes32 root = _sortedPair(LEAF_A1_2_4M, LEAF_B2_600K);
        assertEq(root, TWO_LEAF_ROOT, "two-leaf root");

        // Proof for leaf A is sibling B (Rust tree insertion order A then B).
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = LEAF_B2_600K;
        assertTrue(MerkleProof.verify(proof, TWO_LEAF_ROOT, LEAF_A1_2_4M), "OZ verify A");
        proof[0] = LEAF_A1_2_4M;
        assertTrue(MerkleProof.verify(proof, TWO_LEAF_ROOT, LEAF_B2_600K), "OZ verify B");
    }

    function test_rustSingleLeafRoot_claimPayout_baseline() public {
        // Single-leaf tree: root == leaf. Empty proof.
        uint256 score = 100_000;
        bytes32 root = LEAF_A1_100K;
        assertEq(_solLeaf(workerA1, score), root);

        uint256 epoch = 20260714;
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(epoch, root, keccak256("rust-parity-ev"));
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch);

        bytes32[] memory empty;
        uint256 balBefore = goat.balanceOf(workerA1);
        settle.claimPayout(epoch, workerA1, score, empty);
        assertEq(goat.balanceOf(workerA1), balBefore, "baseline mints 0");
        assertTrue(settle.hasBaseline(workerA1));
        assertEq(settle.lastClaimedCumulative(workerA1), score);
    }

    function test_rustTwoLeafRoot_claimPayout_withProof() public {
        uint256 scoreA = 2_400_000;
        uint256 scoreB = 600_000;
        // Only A1 is enrolled/bound in setUp; B is only for tree structure.
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = LEAF_B2_600K;

        uint256 epoch = 20260715;
        vm.prank(proposer);
        settle.proposeBatch{value: PBOND}(epoch, TWO_LEAF_ROOT, keccak256("rust-2leaf"));
        vm.warp(block.timestamp + WINDOW + 1);
        vm.prank(watcher);
        settle.confirmEpoch(epoch);
        settle.finalizeBatch(epoch);

        // Wrong score with proof for A → BadProof (before successful claim).
        vm.expectRevert(EpochSettlement.BadProof.selector);
        settle.claimPayout(epoch, workerA1, scoreB, proof);

        // Must not revert BadProof — root/proof came from Rust daemon vectors.
        settle.claimPayout(epoch, workerA1, scoreA, proof);
        assertTrue(settle.hasBaseline(workerA1));
        assertEq(settle.lastClaimedCumulative(workerA1), scoreA);
    }
}
