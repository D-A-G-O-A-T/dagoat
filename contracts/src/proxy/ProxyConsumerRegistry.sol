// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {EnrollmentRegistry} from "../EnrollmentRegistry.sol";

/// Consumer enrolment and collateral for the residential proxy revenue lane. [TARGET]
///
/// # There is no public door, and that is the point
///
/// The only way an address enters the consumer set is `enrolConsumer`, which is
/// `onlySafe`. There is deliberately no `register()`, no `registerSelf()`, no
/// `joinAsConsumer()` and no `enrol()`. "First-party consumers only" is therefore a
/// property of the deployed bytecode rather than a promise in a document: opening the
/// marketplace would require deploying different code, not flipping a flag. A test
/// probes those four signatures against the runtime and asserts all four are absent,
/// with `enrolConsumer` present as the positive control.
///
/// # What the stake does and does not deter -- stated plainly
///
/// It **does**: put a bounded, recoverable amount of value at risk behind an account the
/// Policy Safe already chose, so a resolver ruling has something to act on; make the cost
/// of losing a credential to carelessness non-zero; and, because the delay keeps the
/// collateral reachable after the exit is requested, stop a consumer from noticing a
/// pending ruling and leaving with the collateral first.
///
/// It **does not**: verify who anyone is (the identity decision is the Policy Safe's, and
/// membership of the existing enrolment allowlist is read live on every activity check);
/// prove anything about the traffic a consumer actually sends; stop abuse while it is
/// happening -- slashing is after the fact and needs a human resolver to rule; or act as
/// a Sybil defence, because with no public door there are no unsanctioned identities for
/// it to price. A party willing to post the collateral is not thereby trustworthy. The
/// stake is collateral against a counterparty already selected off chain; it is not a
/// substitute for that selection, and no copy anywhere may describe it as one.
///
/// # Composition, not a second identity system
///
/// Enrolment requires the address to already be on the `EnrollmentRegistry` allowlist,
/// and `isActiveConsumer` re-reads that allowlist on every call. Removing an address
/// there deactivates it here immediately, which is why this contract needs no revocation
/// entrypoint of its own and keeps no opinion the allowlist does not already hold.
///
/// This contract custodies the stake token and nothing else. It never touches GOAT, never
/// mints, and holds no path that reduces any token's total supply.
contract ProxyConsumerRegistry is ReentrancyGuard {
    using SafeERC20 for IERC20;

    error NotSafe();
    error NotResolver();
    error ZeroAddress();
    error ZeroRef();
    error ZeroAmount();
    error NotOnAllowlist();
    error AlreadyEnrolled();
    error RefTaken();
    error NotAConsumer();
    error UnstakeAlreadyRequested();
    error NoUnstakeRequested();
    error UnstakeNotReady();
    error AmountExceedsStake();

    /// The Policy Safe. Sole enrolment authority; sole setter of `resolver`.
    address public immutable safe;
    /// The collateral token. Chosen at deploy and never changed.
    IERC20 public immutable stakeToken;
    /// The existing allowlist this contract composes with rather than replaces.
    EnrollmentRegistry public immutable registry;
    /// The one and only destination a slash can send collateral to.
    address public immutable reserveSink;
    /// Collateral floor for an active consumer. Constructor value, no setter.
    uint256 public immutable minStake;
    /// Seconds a requested exit stays slashable before it can be withdrawn.
    /// Constructor value, no setter.
    uint64 public immutable unstakeDelay;

    /// The address permitted to call `slash`. Starts as the Policy Safe so the
    /// contract is operable on day one, and can be pointed at a dispute resolver
    /// later without redeploying.
    address public resolver;

    /// Enrolment reference (a hash of the off-chain record -- no PII on chain) to the
    /// consumer address. One reference, one consumer, both directions.
    mapping(bytes32 => address) public consumerOf;
    mapping(address => bytes32) public refOf;
    mapping(address => bool) public isConsumer;

    /// Collateral currently backing the consumer.
    mapping(address => uint256) public stakeOf;
    /// Collateral whose exit has been requested. Still slashable until withdrawn.
    mapping(address => uint256) public pendingUnstakeOf;
    /// Unix time the pending exit becomes withdrawable.
    mapping(address => uint64) public unstakeReadyAt;

    event ConsumerEnrolled(address indexed consumer, bytes32 indexed consumerRef);
    event ResolverSet(address indexed previousResolver, address indexed newResolver);
    event StakeToppedUp(address indexed consumer, uint256 amount, uint256 newStake);
    event UnstakeRequested(address indexed consumer, uint256 amount, uint64 readyAt);
    event StakeWithdrawn(address indexed consumer, uint256 amount);
    event StakeSlashed(address indexed consumer, uint256 amount, address indexed destination, string reason);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    modifier onlyResolver() {
        if (msg.sender != resolver) revert NotResolver();
        _;
    }

    /// @param safe_ Policy Safe.
    /// @param stakeToken_ collateral token.
    /// @param registry_ the existing enrolment allowlist.
    /// @param reserveSink_ the sole slash destination.
    /// @param minStake_ collateral floor; zero is refused because a free credential
    ///        is not collateral, and the deploy check that reads it back would then
    ///        be asserting nothing.
    /// @param unstakeDelay_ exit delay in seconds; zero is refused because a delay of
    ///        zero lets a consumer withdraw in the same block a ruling is being
    ///        prepared, which removes the only reason the delay exists.
    constructor(
        address safe_,
        address stakeToken_,
        address registry_,
        address reserveSink_,
        uint256 minStake_,
        uint64 unstakeDelay_
    ) {
        if (safe_ == address(0) || stakeToken_ == address(0) || registry_ == address(0) || reserveSink_ == address(0)) revert ZeroAddress();
        if (minStake_ == 0 || unstakeDelay_ == 0) revert ZeroAmount();

        safe = safe_;
        stakeToken = IERC20(stakeToken_);
        registry = EnrollmentRegistry(registry_);
        reserveSink = reserveSink_;
        minStake = minStake_;
        unstakeDelay = unstakeDelay_;
        resolver = safe_;
        emit ResolverSet(address(0), safe_);
    }

    // ---------------------------------------------------------------- governance

    /// The single line that would have to change to open this to the public is the
    /// `onlySafe` on this function. It is here, in the open, on purpose.
    function enrolConsumer(address consumer, bytes32 consumerRef) external onlySafe {
        if (consumer == address(0)) revert ZeroAddress();
        if (consumerRef == bytes32(0)) revert ZeroRef();
        if (isConsumer[consumer]) revert AlreadyEnrolled();
        if (consumerOf[consumerRef] != address(0)) revert RefTaken();
        if (!registry.enrolled(consumer)) revert NotOnAllowlist();

        isConsumer[consumer] = true;
        consumerOf[consumerRef] = consumer;
        refOf[consumer] = consumerRef;
        emit ConsumerEnrolled(consumer, consumerRef);
    }

    function setResolver(address newResolver) external onlySafe {
        if (newResolver == address(0)) revert ZeroAddress();
        address previous = resolver;
        resolver = newResolver;
        emit ResolverSet(previous, newResolver);
    }

    // ------------------------------------------------------------------ consumer

    /// Add collateral. Self-service, but only for an address the Safe already enrolled,
    /// so this is not a side door into the consumer set.
    function topUp(uint256 amount) external nonReentrant {
        if (!isConsumer[msg.sender]) revert NotAConsumer();
        if (amount == 0) revert ZeroAmount();

        uint256 newStake = stakeOf[msg.sender] + amount;
        stakeOf[msg.sender] = newStake;
        stakeToken.safeTransferFrom(msg.sender, address(this), amount);
        emit StakeToppedUp(msg.sender, amount, newStake);
    }

    /// Request the exit of the whole active stake. The consumer is inactive from this
    /// call onward -- `stakeOf` drops to zero -- while the collateral itself stays in
    /// this contract, and stays slashable, for `unstakeDelay` seconds.
    function requestUnstake() external {
        if (!isConsumer[msg.sender]) revert NotAConsumer();
        if (pendingUnstakeOf[msg.sender] != 0) revert UnstakeAlreadyRequested();

        uint256 amount = stakeOf[msg.sender];
        if (amount == 0) revert ZeroAmount();

        stakeOf[msg.sender] = 0;
        pendingUnstakeOf[msg.sender] = amount;
        uint64 readyAt = uint64(block.timestamp) + unstakeDelay;
        unstakeReadyAt[msg.sender] = readyAt;
        emit UnstakeRequested(msg.sender, amount, readyAt);
    }

    /// Collect a requested exit once the delay has elapsed. Pays out whatever survived
    /// any slash during the window, which may be less than was requested and may be
    /// nothing at all.
    function withdraw() external nonReentrant {
        uint256 amount = pendingUnstakeOf[msg.sender];
        if (amount == 0) revert NoUnstakeRequested();
        if (block.timestamp < unstakeReadyAt[msg.sender]) revert UnstakeNotReady();

        pendingUnstakeOf[msg.sender] = 0;
        unstakeReadyAt[msg.sender] = 0;
        stakeToken.safeTransfer(msg.sender, amount);
        emit StakeWithdrawn(msg.sender, amount);
    }

    // ------------------------------------------------------------------- resolver

    /// Move collateral to `reserveSink`. There is no destination argument: the sink is
    /// immutable, so a compromised resolver can move a consumer's collateral to the
    /// reserve and nowhere else -- not one unit of it to itself. The collateral stays in
    /// circulation; it changes custodian.
    ///
    /// Active stake is taken first, then any pending exit, so requesting an exit is not
    /// an escape from a ruling that has not landed yet.
    function slash(address consumer, uint256 amount, string calldata reason) external onlyResolver nonReentrant {
        if (!isConsumer[consumer]) revert NotAConsumer();
        if (amount == 0) revert ZeroAmount();

        uint256 active = stakeOf[consumer];
        uint256 pending = pendingUnstakeOf[consumer];
        if (amount > active + pending) revert AmountExceedsStake();

        uint256 fromActive = amount > active ? active : amount;
        stakeOf[consumer] = active - fromActive;
        uint256 fromPending = amount - fromActive;
        if (fromPending != 0) {
            pendingUnstakeOf[consumer] = pending - fromPending;
        }

        stakeToken.safeTransfer(reserveSink, amount);
        emit StakeSlashed(consumer, amount, reserveSink, reason);
    }

    // ---------------------------------------------------------------------- views

    /// Three conditions, all live: enrolled here, still on the shared allowlist, and
    /// collateralised to the floor. Any one of them failing deactivates the consumer
    /// without a transaction against this contract.
    function isActiveConsumer(address consumer) external view returns (bool) {
        return isConsumer[consumer] && registry.enrolled(consumer) && stakeOf[consumer] >= minStake;
    }

    /// Everything a resolver could still take: active stake plus a pending exit that has
    /// not been collected.
    function slashableStakeOf(address consumer) external view returns (uint256) {
        return stakeOf[consumer] + pendingUnstakeOf[consumer];
    }
}
