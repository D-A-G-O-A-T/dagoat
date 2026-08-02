// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

/// Settlement for the allowlisted fetch network.
///
/// THIS CONTRACT MOVES GOAT THAT ALREADY EXISTS. It is not a minter, it holds no
/// minter role, and it has no path to one. Bandwidth moved is not verified
/// public-good work and does not satisfy either limb of the proof-of-valued-work
/// gate, so the operator share is a transfer out of a pre-funded pool -- see the
/// "The No-Ponzi Invariant — GoatCoin's load-bearing economic rule" spec, §1.
///
/// IT ALSO HAS NO BURN. Not a parameter set to zero, not a disabled branch: there
/// is no burn function, no burn constant, no burn event and no dead-address sink
/// anywhere in this file. An absent mechanism cannot be enabled by a later
/// governance call, which is the entire point of making it absent.
///
/// The absence is a PROPERTY, not a vocabulary rule, and the property is that no
/// GOAT is unreachable. `releaseReserve` and `sweepUnclaimed` exist for exactly
/// that reason: a `reserveHeld` counter that only ever goes up, with no withdrawal
/// path, is a supply sink whether or not anything is named after one -- and an
/// "insurance buffer" nobody can draw on is not insurance. The contract's GOAT
/// balance is always exactly the sum of what someone can still take out, and a test
/// asserts it lands on zero.
///
/// The 10% take has THREE on-chain destinations: `treasury` (600 bps of gross) and
/// `attestorSafe` (200 bps), both sub-lines of that spec's §8 *protocol operations*
/// component, and `reserveHeld` (200 bps), its *reserve / insurance buffer*. The
/// third §8 component -- value accrual by supply destruction -- is deleted by
/// founder ruling FR-1 and claimed nowhere. Whether 10% is still the right rate once
/// that component is gone is a founder question, recorded as D-9, not a number this
/// contract quietly keeps.
///
/// The take is DERIVED, never supplied: `proposeBatch` commits `grossGoatWei` beside
/// the root and `finalizeBatch` takes no amount argument. A caller-supplied take on
/// an unauthenticated entrypoint is a permissionless drain.
///
/// The solvency rule is a require, not a policy, and it is checked PER EPOCH before
/// it is checked globally, because `reward_pool(w) <= external_inflow(w) - reserve(w)`
/// is a statement about a window.
contract ProxyRevenueSettlement is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ---------------------------------------------------------------- errors
    error NotSafe();
    error NotFunder();
    error NotPublisher();
    error NotGateway();
    error NotResolver();
    error NotEnrolled();
    error NotReserveSink();
    error ZeroAddress();
    error ZeroAmount();
    error EpochNotInProxySpace();
    error BackingExceedsInflow();
    error BackingBelowReferenceRate();
    error RootAlreadyPublished();
    error RootMissing();
    error BadStatus();
    error BadBond();
    error WindowOpen();
    error WindowClosed();
    error BadProof();
    error AlreadyClaimed();
    error PoolWouldBeOverdrawn();
    error OperatorShareExceeded();
    error GrossExceedsFunding();
    error NothingToWithdraw();

    // ------------------------------------------------------------- constants
    bytes32 public constant PROXY_LEAF_DOMAIN = keccak256("GOAT_PROXY_REVENUE_LEAF_V1");
    uint256 public constant PROXY_EPOCH_BASE = 8_000_000_000_000;
    uint256 public constant PROXY_EPOCH_CEILING = 9_000_000_000_000;
    uint16 public constant OPERATOR_BPS = 9_000;
    uint16 public constant TAKE_BPS = 1_000;
    uint16 public constant TREASURY_BPS = 600;
    uint16 public constant ATTESTOR_BPS = 200;
    uint16 public constant RESERVE_BPS = 200;
    uint16 public constant BPS_DENOM = 10_000;

    enum Status {
        None,
        Proposed,
        Challenged,
        ProposerWon,
        ChallengerWon,
        Finalized
    }

    struct Config {
        address safe;
        address goat;
        address registry;
        address treasury;
        address attestorSafe;
        address reserveSink;
        address funder;
        address publisher;
        address gateway;
        address usdtTreasury;
        address resolver;
        address watcher;
        uint64 challengeWindow;
        uint64 claimWindow;
        uint64 resolveWindow;
        uint256 proposerBond;
        uint256 challengerBond;
        uint256 referenceRateUsdtPerGoat;
    }

    struct Funding {
        uint256 goatFunded;
        uint256 usdtBacked;
        uint256 usdtInflow;
        /// Per-epoch, so the window inequality is enforced on the window.
        uint256 goatClaimed;
        uint256 reserveHeld;
    }

    struct Batch {
        bytes32 root;
        bytes32 evidenceRef;
        uint64 proposedAt;
        address proposer;
        address challenger;
        Status status;
        /// Committed at propose time. The take is derived from this and from
        /// nothing a caller supplies later.
        uint256 grossGoatWei;
        uint256 takeSettled;
        uint256 claimedGoatWei;
        /// Snapshotted so a later `setBonds` / `setWindows` cannot strand a posted
        /// bond or retroactively close an open claim window.
        uint256 proposerBondPosted;
        uint256 challengerBondPosted;
        uint64 challengeWindowSnap;
        uint64 claimWindowSnap;
        uint64 resolveWindowSnap;
    }

    // ----------------------------------------------------------------- state
    address public immutable safe;
    IERC20 public immutable goat;
    address public immutable registry;
    address public immutable treasury;
    address public immutable attestorSafe;
    address public immutable reserveSink;
    address public immutable publisher;
    address public immutable gateway;
    address public immutable usdtTreasury;
    address public immutable resolver;
    address public immutable watcher;

    /// NOT immutable, and one-way per address. `funder` as an immutable made
    /// Option B unarmable on a settlement deployed for Option A: the treasury's
    /// own `fundSettlement` requires the settlement to name it as funder, and the
    /// only route to that was a redeploy that orphans every published root.
    mapping(address => bool) public isFunder;

    uint64 public challengeWindow;
    uint64 public claimWindow;
    uint64 public resolveWindow;
    uint256 public proposerBond;
    uint256 public challengerBond;
    uint256 public referenceRateUsdtPerGoat;

    uint256 public totalFunded;
    uint256 public totalClaimed;
    uint256 public reserveHeld;

    mapping(uint256 => Funding) public fundingOf;
    mapping(uint256 => Batch) public batchOf;
    mapping(uint256 => mapping(address => bool)) public claimed;
    /// Bonds are PULL payments: a recipient that reverts on `receive()` must not be
    /// able to brick `resolveChallenge` and wedge an epoch in `Challenged` forever.
    mapping(address => uint256) public bondCredit;

    // ---------------------------------------------------------------- events
    event FunderSet(address indexed funder);
    event UsdtInflowRecorded(uint256 indexed epochId, uint256 amount);
    event EpochFunded(uint256 indexed epochId, uint256 goatAmount, uint256 backedUsdt);
    event BatchProposed(
        uint256 indexed epochId, bytes32 root, bytes32 evidenceRef, address proposer, uint256 grossGoatWei
    );
    event BatchChallenged(uint256 indexed epochId, address challenger, bytes32 counterRoot);
    event ChallengeResolved(uint256 indexed epochId, bool proposerWon);
    event ChallengeTimedOut(uint256 indexed epochId);
    event BatchReset(uint256 indexed epochId);
    event BatchFinalized(uint256 indexed epochId, uint256 takeSettled);
    event TakeRouted(uint256 indexed epochId, uint256 toTreasury, uint256 toAttestor, uint256 toReserve);
    event PayoutClaimed(uint256 indexed epochId, address indexed operator, uint256 totalBytes, uint256 payoutGoatWei);
    event ReserveReleased(address indexed to, uint256 amount);
    event UnclaimedSwept(uint256 indexed epochId, address indexed to, uint256 amount);
    event BondWithdrawn(address indexed to, uint256 amount);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    /// The publisher proposes and finalizes; the Safe may do either as a fallback,
    /// so a lost publisher key does not strand an epoch.
    modifier onlyPublisher() {
        if (msg.sender != publisher && msg.sender != safe) revert NotPublisher();
        _;
    }

    constructor(Config memory c) {
        if (
            c.safe == address(0) || c.goat == address(0) || c.registry == address(0) || c.treasury == address(0)
                || c.attestorSafe == address(0) || c.reserveSink == address(0) || c.funder == address(0)
                || c.publisher == address(0) || c.gateway == address(0) || c.usdtTreasury == address(0)
                || c.resolver == address(0) || c.watcher == address(0)
        ) revert ZeroAddress();
        safe = c.safe;
        goat = IERC20(c.goat);
        registry = c.registry;
        treasury = c.treasury;
        attestorSafe = c.attestorSafe;
        reserveSink = c.reserveSink;
        publisher = c.publisher;
        gateway = c.gateway;
        usdtTreasury = c.usdtTreasury;
        resolver = c.resolver;
        watcher = c.watcher;
        isFunder[c.funder] = true;
        emit FunderSet(c.funder);
        challengeWindow = c.challengeWindow;
        claimWindow = c.claimWindow;
        resolveWindow = c.resolveWindow;
        proposerBond = c.proposerBond;
        challengerBond = c.challengerBond;
        referenceRateUsdtPerGoat = c.referenceRateUsdtPerGoat;
    }

    function _requireProxyEpoch(uint256 epochId) internal pure {
        if (epochId < PROXY_EPOCH_BASE || epochId >= PROXY_EPOCH_CEILING) revert EpochNotInProxySpace();
    }

    /// One-way, per address. Arming Option B later is a Safe transaction, not a
    /// redeploy.
    function setFunder(address funder_) external onlySafe {
        if (funder_ == address(0)) revert ZeroAddress();
        isFunder[funder_] = true;
        emit FunderSet(funder_);
    }

    /// The gateway is the only party that sees consumer settlement land. It reports
    /// it here so that funding is bounded by something the funder cannot assert.
    ///
    /// HONEST BOUND, also stated in INV-15 and D-10: no USDT touches this contract.
    /// This is a gateway attestation, not an escrow, and the inequality below is
    /// therefore structural only downstream of it.
    function recordUsdtInflow(uint256 epochId, uint256 amount) external {
        _requireProxyEpoch(epochId);
        if (msg.sender != gateway && msg.sender != usdtTreasury) revert NotGateway();
        if (amount == 0) revert ZeroAmount();
        fundingOf[epochId].usdtInflow += amount;
        emit UsdtInflowRecorded(epochId, amount);
    }

    /// Moves GOAT the funder ALREADY HOLDS into the payable pool. No mint.
    ///
    /// Two bounds, not one. `usdtBacked <= usdtInflow` stops a funder claiming
    /// backing that was never reported; the reference-rate bound stops it declaring
    /// a million GOAT backed by one USDT-wei. Without the second, the first bounds
    /// nothing that matters.
    function fundEpoch(uint256 epochId, uint256 goatAmount, uint256 backedUsdt) external nonReentrant {
        _requireProxyEpoch(epochId);
        if (!isFunder[msg.sender]) revert NotFunder();
        if (goatAmount == 0) revert ZeroAmount();
        Funding storage f = fundingOf[epochId];
        if (f.usdtBacked + backedUsdt > f.usdtInflow) revert BackingExceedsInflow();
        if (goatAmount * referenceRateUsdtPerGoat > backedUsdt * 1e18) revert BackingBelowReferenceRate();
        f.usdtBacked += backedUsdt;
        f.goatFunded += goatAmount;
        totalFunded += goatAmount;
        goat.safeTransferFrom(msg.sender, address(this), goatAmount);
        emit EpochFunded(epochId, goatAmount, backedUsdt);
    }

    /// `grossGoatWei` is the epoch's total gross the leaves were derived from. It is
    /// committed HERE so that `finalizeBatch` can derive the take and so that the
    /// sum of leaf payouts is bounded by `gross * OPERATOR_BPS / BPS_DENOM`.
    function proposeBatch(uint256 epochId, bytes32 root, bytes32 evidenceRef, uint256 grossGoatWei)
        external
        payable
        nonReentrant
        onlyPublisher
    {
        _requireProxyEpoch(epochId);
        if (msg.value != proposerBond) revert BadBond();
        if (grossGoatWei == 0) revert ZeroAmount();
        Batch storage b = batchOf[epochId];
        if (b.status != Status.None) revert RootAlreadyPublished();
        b.root = root;
        b.evidenceRef = evidenceRef;
        b.proposedAt = uint64(block.timestamp);
        b.proposer = msg.sender;
        b.status = Status.Proposed;
        b.grossGoatWei = grossGoatWei;
        b.claimedGoatWei = 0;
        b.takeSettled = 0;
        b.proposerBondPosted = msg.value;
        b.challengerBondPosted = 0;
        b.challenger = address(0);
        b.challengeWindowSnap = challengeWindow;
        b.claimWindowSnap = claimWindow;
        b.resolveWindowSnap = resolveWindow;
        emit BatchProposed(epochId, root, evidenceRef, msg.sender, grossGoatWei);
    }

    /// Permissionless by design: anyone who can prove a batch wrong should be able
    /// to say so. `timeoutChallenge` is what stops that being a denial of service.
    function challengeBatch(uint256 epochId, bytes32 counterRoot) external payable nonReentrant {
        _requireProxyEpoch(epochId);
        Batch storage b = batchOf[epochId];
        if (b.status != Status.Proposed) revert BadStatus();
        if (block.timestamp > b.proposedAt + b.challengeWindowSnap) revert WindowClosed();
        if (msg.value != challengerBond) revert BadBond();
        b.challenger = msg.sender;
        b.challengerBondPosted = msg.value;
        b.status = Status.Challenged;
        emit BatchChallenged(epochId, msg.sender, counterRoot);
    }

    /// Slashed bonds go to the RESERVE -- never to the challenger, never destroyed.
    /// A bounty would price the act of challenging and invite frivolous challenges
    /// against honest proposers whose only defence is gas.
    ///
    /// Amounts come from the BATCH, not from live storage: a `setBonds` between
    /// propose and resolve would otherwise over-pay out of other batches' posted ETH
    /// or under-pay and strand it.
    function resolveChallenge(uint256 epochId, bool proposerWon) external nonReentrant {
        _requireProxyEpoch(epochId);
        if (msg.sender != resolver) revert NotResolver();
        Batch storage b = batchOf[epochId];
        if (b.status != Status.Challenged) revert BadStatus();
        if (proposerWon) {
            b.status = Status.ProposerWon;
            bondCredit[b.proposer] += b.proposerBondPosted;
            bondCredit[reserveSink] += b.challengerBondPosted;
        } else {
            b.status = Status.ChallengerWon;
            bondCredit[b.challenger] += b.challengerBondPosted;
            bondCredit[reserveSink] += b.proposerBondPosted;
        }
        b.proposerBondPosted = 0;
        b.challengerBondPosted = 0;
        emit ChallengeResolved(epochId, proposerWon);
    }

    /// A challenge nobody resolves is a challenge that freezes an epoch's funding
    /// for the price of one bond. Past the resolve window it defaults to the
    /// proposer and the abandoned bond is slashed to the reserve.
    function timeoutChallenge(uint256 epochId) external nonReentrant {
        _requireProxyEpoch(epochId);
        Batch storage b = batchOf[epochId];
        if (b.status != Status.Challenged) revert BadStatus();
        if (block.timestamp <= uint256(b.proposedAt) + b.challengeWindowSnap + b.resolveWindowSnap) {
            revert WindowOpen();
        }
        b.status = Status.ProposerWon;
        bondCredit[b.proposer] += b.proposerBondPosted;
        bondCredit[reserveSink] += b.challengerBondPosted;
        b.proposerBondPosted = 0;
        b.challengerBondPosted = 0;
        emit ChallengeTimedOut(epochId);
    }

    /// A batch the challenger won is WRONG, not settled: without this, every honest
    /// operator in that epoch is uncompensated forever and the epoch's funding is
    /// stuck. Reopening lets a corrected root be proposed.
    function resetBatch(uint256 epochId) external onlySafe {
        _requireProxyEpoch(epochId);
        Batch storage b = batchOf[epochId];
        if (b.status != Status.ChallengerWon) revert BadStatus();
        delete batchOf[epochId];
        emit BatchReset(epochId);
    }

    function withdrawBond() external nonReentrant {
        uint256 amount = bondCredit[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        bondCredit[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "bond withdrawal failed");
        emit BondWithdrawn(msg.sender, amount);
    }

    /// Routes the protocol take and books the reserve. Takes NO amount: every share
    /// is derived from the gross committed at propose time, through BPS_DENOM.
    /// Three destinations, and the third is a SUBTRACTION from what claims may ever
    /// reach -- `reserveHeld` is never decremented by a claim (only by
    /// `releaseReserve`, which is the Safe's, not a claimant's).
    function finalizeBatch(uint256 epochId) external nonReentrant onlyPublisher {
        _requireProxyEpoch(epochId);
        Batch storage b = batchOf[epochId];
        if (b.status == Status.Proposed) {
            if (block.timestamp <= b.proposedAt + b.challengeWindowSnap) revert WindowOpen();
        } else if (b.status != Status.ProposerWon) {
            revert BadStatus();
        }
        Funding storage f = fundingOf[epochId];
        if (b.grossGoatWei > f.goatFunded) revert GrossExceedsFunding();

        uint256 takeGoatWei = (b.grossGoatWei * TAKE_BPS) / BPS_DENOM;
        uint256 toTreasury = (b.grossGoatWei * TREASURY_BPS) / BPS_DENOM;
        uint256 toAttestor = (b.grossGoatWei * ATTESTOR_BPS) / BPS_DENOM;
        uint256 toReserve = takeGoatWei - toTreasury - toAttestor;

        b.status = Status.Finalized;
        b.takeSettled = takeGoatWei;
        f.reserveHeld += toReserve;
        f.goatClaimed += toTreasury + toAttestor;
        reserveHeld += toReserve;
        totalClaimed += toTreasury + toAttestor;
        if (f.goatClaimed + f.reserveHeld > f.goatFunded) revert PoolWouldBeOverdrawn();
        if (totalClaimed + reserveHeld > totalFunded) revert PoolWouldBeOverdrawn();

        bondCredit[b.proposer] += b.proposerBondPosted;
        b.proposerBondPosted = 0;

        goat.safeTransfer(treasury, toTreasury);
        goat.safeTransfer(attestorSafe, toAttestor);
        emit TakeRouted(epochId, toTreasury, toAttestor, toReserve);
        emit BatchFinalized(epochId, takeGoatWei);
    }

    /// THE No-Ponzi require, twice. Written as an addition on the left so it cannot
    /// underflow and mask the state it exists to catch, and checked PER EPOCH before
    /// it is checked globally -- the window form is the one the invariant states, and
    /// the global form alone would let an unfunded epoch draw on a funded one.
    function claim(
        uint256 epochId,
        address operator,
        uint256 totalBytes,
        uint256 payoutGoatWei,
        bytes32[] calldata proof
    ) external nonReentrant {
        _requireProxyEpoch(epochId);
        Batch storage b = batchOf[epochId];
        if (b.status != Status.Finalized) revert BadStatus();
        if (block.timestamp > uint256(b.proposedAt) + b.challengeWindowSnap + b.claimWindowSnap) {
            revert WindowClosed();
        }
        if (b.root == bytes32(0)) revert RootMissing();
        if (claimed[epochId][operator]) revert AlreadyClaimed();
        if (payoutGoatWei == 0) revert ZeroAmount();
        if (!IProxyEnrollment(registry).enrolled(operator)) revert NotEnrolled();

        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(PROXY_LEAF_DOMAIN, operator, epochId, totalBytes, payoutGoatWei)))
        );
        if (!MerkleProof.verify(proof, b.root, leaf)) revert BadProof();

        Funding storage f = fundingOf[epochId];
        if (f.goatClaimed + payoutGoatWei > f.goatFunded - f.reserveHeld) revert PoolWouldBeOverdrawn();
        if (totalClaimed + payoutGoatWei > totalFunded - reserveHeld) revert PoolWouldBeOverdrawn();
        if (b.claimedGoatWei + payoutGoatWei > (b.grossGoatWei * OPERATOR_BPS) / BPS_DENOM) {
            revert OperatorShareExceeded();
        }

        claimed[epochId][operator] = true;
        b.claimedGoatWei += payoutGoatWei;
        f.goatClaimed += payoutGoatWei;
        totalClaimed += payoutGoatWei;
        goat.safeTransfer(operator, payoutGoatWei);
        emit PayoutClaimed(epochId, operator, totalBytes, payoutGoatWei);
    }

    /// The reserve is spendable BY THE SAFE, to the reserve sink, and to nowhere
    /// else. Without this the reserve is a one-way sink and the "insurance buffer"
    /// §8 component this path claims does not exist.
    function releaseReserve(address to, uint256 amount) external onlySafe nonReentrant {
        if (to != reserveSink) revert NotReserveSink();
        if (amount == 0 || amount > reserveHeld) revert ZeroAmount();
        reserveHeld -= amount;
        goat.safeTransfer(to, amount);
        emit ReserveReleased(to, amount);
    }

    /// GOAT nobody claimed before the window closed returns to a funder. Without it,
    /// every unclaimed leaf is GOAT locked in this contract forever.
    function sweepUnclaimed(uint256 epochId, address to) external onlySafe nonReentrant {
        _requireProxyEpoch(epochId);
        if (!isFunder[to]) revert NotFunder();
        Batch storage b = batchOf[epochId];
        if (b.status != Status.Finalized) revert BadStatus();
        if (block.timestamp <= uint256(b.proposedAt) + b.challengeWindowSnap + b.claimWindowSnap) {
            revert WindowOpen();
        }
        Funding storage f = fundingOf[epochId];
        uint256 amount = f.goatFunded - f.goatClaimed - f.reserveHeld;
        if (amount == 0) revert ZeroAmount();
        f.goatClaimed += amount;
        totalClaimed += amount;
        goat.safeTransfer(to, amount);
        emit UnclaimedSwept(epochId, to, amount);
    }

    function rootOf(uint256 epochId) external view returns (bytes32) {
        return batchOf[epochId].root;
    }

    function statusOf(uint256 epochId) external view returns (Status) {
        return batchOf[epochId].status;
    }

    /// A thin view so the invariant handler need not decompose a struct getter.
    function fundingOfGoatFunded(uint256 epochId) external view returns (uint256) {
        return fundingOf[epochId].goatFunded;
    }

    function setWindows(uint64 challengeWindow_, uint64 claimWindow_, uint64 resolveWindow_) external onlySafe {
        challengeWindow = challengeWindow_;
        claimWindow = claimWindow_;
        resolveWindow = resolveWindow_;
    }

    function setBonds(uint256 proposerBond_, uint256 challengerBond_) external onlySafe {
        proposerBond = proposerBond_;
        challengerBond = challengerBond_;
    }

    /// A governance number that BOUNDS funding against realized inflow, enforced by
    /// the `BackingBelowReferenceRate` require in `fundEpoch`. It is not a price, not
    /// a peg, and not a promise; there is no oracle behind it.
    function setReferenceRate(uint256 rate) external onlySafe {
        referenceRateUsdtPerGoat = rate;
    }

    receive() external payable {}
}

/// The enrolment flag this contract reads. Declared as a minimal interface rather
/// than importing the registry, so the payout path costs one `staticcall` and no
/// extra bytecode. Naming the existing on-chain identifier is the vocabulary law's
/// one carve-out: this is a quotation of a deployed contract, not a design term.
interface IProxyEnrollment {
    function enrolled(address account) external view returns (bool);
}
