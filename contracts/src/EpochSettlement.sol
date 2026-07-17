// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GoatCoin} from "./GoatCoin.sol";
import {HoldbackEscrow} from "./HoldbackEscrow.sol";
import {EnrollmentRegistry} from "./EnrollmentRegistry.sol";
import {WorkerBinding} from "./WorkerBinding.sol";
import {IDisputeResolver} from "./IDisputeResolver.sol";
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";

/// Optimistic, permissionless settlement of FAH score-delta payouts (spec 2026-07-13 +
/// FAH-attribution plan 2026-07-14: baseline via first claim, time-based capPerDay).
contract EpochSettlement {
    error NotSafe();
    error NotResolver();
    error NotWatcher();
    error BadArg();
    error WrongStatus();
    error WindowOpen();
    error WindowClosed();
    error NotConfirmed();
    error BondMismatch();
    error NotEnrolled();
    error NotBound();
    error BadProof();
    error TransferFailed();

    // immutable
    address public immutable safe;
    GoatCoin public immutable goat;
    HoldbackEscrow public immutable escrow;
    EnrollmentRegistry public immutable registry;
    WorkerBinding public immutable binding;
    uint16 public immutable holdbackBps;
    uint64 public immutable holdbackBackstop;

    // adjustable params
    uint256 public rate; // GOAT wei per score unit
    /// Max GOAT (wei) mintable per worker per day (time-based rate cap). Founder: 67e18.
    uint256 public capPerDay;
    uint256 public keeperFee; // GOAT wei paid to msg.sender (the auto-claim keeper) per liquid claim; default 0.
    /// @dev Deprecated alias retained for storage layout / deploy scripts: maps to score-unit
    /// ceiling used only when capPerDay == 0 (legacy). Prefer capPerDay.
    uint256 public epochCap;
    uint64 public challengeWindow;
    uint256 public proposerBond;
    uint256 public challengerBond;
    address public resolver;
    address public watcher;
    uint64 public watcherGrace;

    enum Status {
        None,
        Proposed,
        Challenged,
        ProposerWon,
        ChallengerWon,
        Finalized
    }

    struct Batch {
        address proposer;
        uint256 proposerBond;
        address challenger;
        uint256 challengerBond;
        bytes32 merkleRoot;
        uint256 rate; // snapshot of rate at propose time (never retroactive)
        bytes32 evidenceRef;
        uint64 challengeDeadline;
        uint64 watcherConfirmedAt;
        Status status;
    }

    mapping(uint256 => Batch) public batches;
    mapping(address => uint256) public lastClaimedCumulative;
    mapping(uint256 => mapping(address => bool)) public claimed;
    /// First claimPayout stamps baseline (mint 0) and sets this true (INV-1).
    mapping(address => bool) public hasBaseline;
    /// For time-based cap: must be set at baseline claim (INV rate-cap).
    mapping(address => uint64) public lastClaimTime;

    event Proposed(
        uint256 indexed epoch,
        address indexed proposer,
        bytes32 merkleRoot,
        uint256 rate,
        bytes32 evidenceRef,
        uint64 challengeDeadline
    );
    event Challenged(uint256 indexed epoch, address indexed challenger, bytes32 counterEvidenceRef);
    event DisputeSettled(uint256 indexed epoch, bool proposerWon, bytes32 reasonRef);
    event WatcherConfirmed(uint256 indexed epoch, uint64 at);
    event Finalized(uint256 indexed epoch);
    event Reopened(uint256 indexed epoch);
    event Claimed(
        uint256 indexed epoch, address indexed worker, uint256 liquid, uint256 holdback, uint256 newCumulative
    );
    event KeeperFeePaid(uint256 indexed epoch, address indexed worker, address indexed keeper, uint256 fee);
    event BaselineSet(address indexed worker, uint256 baselineScore, uint256 epoch);
    event WorkerSkipped(uint256 indexed epoch, address indexed worker);
    event ParamSet(bytes32 indexed key, uint256 value);
    event AddrSet(bytes32 indexed key, address value);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(
        address safe_,
        GoatCoin goat_,
        HoldbackEscrow escrow_,
        EnrollmentRegistry registry_,
        WorkerBinding binding_,
        uint16 holdbackBps_,
        uint64 holdbackBackstop_,
        uint256 rate_,
        uint256 capPerDay_,
        uint64 challengeWindow_,
        uint256 proposerBond_,
        uint256 challengerBond_,
        address resolver_,
        address watcher_
    ) {
        if (
            safe_ == address(0) || address(goat_) == address(0) || address(escrow_) == address(0)
                || address(registry_) == address(0) || address(binding_) == address(0) || watcher_ == address(0)
        ) revert BadArg();
        if (holdbackBps_ > 10_000 || rate_ == 0) revert BadArg();
        safe = safe_;
        goat = goat_;
        escrow = escrow_;
        registry = registry_;
        binding = binding_;
        holdbackBps = holdbackBps_;
        holdbackBackstop = holdbackBackstop_;
        rate = rate_;
        capPerDay = capPerDay_;
        epochCap = type(uint256).max; // unused when capPerDay > 0; kept for legacy reads
        challengeWindow = challengeWindow_;
        proposerBond = proposerBond_;
        challengerBond = challengerBond_;
        resolver = resolver_;
        watcher = watcher_;
        watcherGrace = 1 days;
    }

    function setRate(uint256 v) external onlySafe {
        if (v == 0) revert BadArg();
        rate = v;
        emit ParamSet("rate", v);
    }

    function setCapPerDay(uint256 v) external onlySafe {
        capPerDay = v;
        emit ParamSet("capPerDay", v);
    }

    function setKeeperFee(uint256 v) external onlySafe {
        keeperFee = v;
        emit ParamSet("keeperFee", v);
    }

    /// @dev Legacy setter; prefer setCapPerDay. Still updates epochCap for tooling that reads it.
    function setEpochCap(uint256 v) external onlySafe {
        epochCap = v;
        emit ParamSet("cap", v);
    }

    function setChallengeWindow(uint64 v) external onlySafe {
        challengeWindow = v;
        emit ParamSet("window", v);
    }

    function setBonds(uint256 p, uint256 c) external onlySafe {
        proposerBond = p;
        challengerBond = c;
        emit ParamSet("pbond", p);
        emit ParamSet("cbond", c);
    }

    function setResolver(address v) external onlySafe {
        if (v == address(0)) revert BadArg();
        resolver = v;
        emit AddrSet("resolver", v);
    }

    function setWatcher(address v) external onlySafe {
        if (v == address(0)) revert BadArg();
        watcher = v;
        emit AddrSet("watcher", v);
    }

    function setWatcherGrace(uint64 v) external onlySafe {
        watcherGrace = v;
        emit ParamSet("watcherGrace", v);
    }

    function proposeBatch(uint256 epoch, bytes32 merkleRoot, bytes32 evidenceRef) external payable {
        Batch storage b = batches[epoch];
        if (!(b.status == Status.None || b.status == Status.ChallengerWon)) revert WrongStatus();
        if (merkleRoot == bytes32(0)) revert BadArg();
        if (msg.value != proposerBond) revert BondMismatch();
        b.proposer = msg.sender;
        b.proposerBond = msg.value;
        b.challenger = address(0);
        b.challengerBond = 0;
        b.merkleRoot = merkleRoot;
        b.rate = rate;
        b.evidenceRef = evidenceRef;
        b.challengeDeadline = uint64(block.timestamp) + challengeWindow;
        b.watcherConfirmedAt = 0;
        b.status = Status.Proposed;
        emit Proposed(epoch, msg.sender, merkleRoot, rate, evidenceRef, b.challengeDeadline);
    }

    function challengeBatch(uint256 epoch, bytes32 counterEvidenceRef) external payable {
        Batch storage b = batches[epoch];
        if (b.status != Status.Proposed) revert WrongStatus();
        if (block.timestamp > b.challengeDeadline) revert WindowClosed();
        if (msg.value != challengerBond) revert BondMismatch();
        b.challenger = msg.sender;
        b.challengerBond = msg.value;
        b.status = Status.Challenged;
        emit Challenged(epoch, msg.sender, counterEvidenceRef);
        IDisputeResolver(resolver).onDispute(epoch, b.proposer, msg.sender);
    }

    function settleDispute(uint256 epoch, bool proposerWon, bytes32 reasonRef) external {
        if (msg.sender != resolver) revert NotResolver();
        Batch storage b = batches[epoch];
        if (b.status != Status.Challenged) revert WrongStatus();
        emit DisputeSettled(epoch, proposerWon, reasonRef);
        if (proposerWon) {
            uint256 award = b.challengerBond;
            b.challengerBond = 0;
            b.status = Status.ProposerWon;
            _send(b.proposer, award);
        } else {
            uint256 award = b.proposerBond + b.challengerBond;
            b.proposerBond = 0;
            b.challengerBond = 0;
            b.status = Status.ChallengerWon;
            emit Reopened(epoch);
            _send(b.challenger, award);
        }
    }

    function confirmEpoch(uint256 epoch) external {
        if (msg.sender != watcher) revert NotWatcher();
        Batch storage b = batches[epoch];
        if (!(b.status == Status.Proposed || b.status == Status.ProposerWon)) revert WrongStatus();
        if (block.timestamp <= b.challengeDeadline) revert WindowOpen();
        b.watcherConfirmedAt = uint64(block.timestamp);
        emit WatcherConfirmed(epoch, b.watcherConfirmedAt);
    }

    function finalizeBatch(uint256 epoch) external {
        Batch storage b = batches[epoch];
        if (!(b.status == Status.Proposed || b.status == Status.ProposerWon)) revert WrongStatus();
        if (block.timestamp <= b.challengeDeadline) revert WindowOpen();
        bool timedOut = block.timestamp > uint256(b.challengeDeadline) + watcherGrace;
        if (b.watcherConfirmedAt == 0 && !timedOut) revert NotConfirmed();
        uint256 bond = b.proposerBond;
        b.proposerBond = 0;
        b.status = Status.Finalized;
        emit Finalized(epoch);
        _send(b.proposer, bond);
    }

    function _send(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = payable(to).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Pull-claim GOAT against a finalized batch leaf.
    /// Baseline (first claim ever): mint 0, stamp watermark + lastClaimTime (INV-1).
    /// Later claims: time-based GOAT rate cap (capPerDay), non-forfeiting score watermark.
    function claimPayout(uint256 epoch, address worker, uint256 provenCumulativeScore, bytes32[] calldata proof)
        external
    {
        Batch storage b = batches[epoch];
        if (b.status != Status.Finalized) revert WrongStatus();
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(worker, provenCumulativeScore))));
        if (!MerkleProof.verify(proof, b.merkleRoot, leaf)) revert BadProof();
        if (!registry.enrolled(worker)) {
            emit WorkerSkipped(epoch, worker);
            return;
        }
        // One claim per (epoch, worker) — MUST run before baseline branch (consultant §2c).
        if (claimed[epoch][worker]) return;

        // Binding required so challengers can map wallet → GOAT-username.
        if (!binding.bound(worker)) revert NotBound();

        // ---- Baseline init (mint 0) — this claim IS the enrollment snapshot ----
        if (!hasBaseline[worker]) {
            lastClaimedCumulative[worker] = provenCumulativeScore;
            hasBaseline[worker] = true;
            lastClaimTime[worker] = uint64(block.timestamp);
            claimed[epoch][worker] = true;
            emit BaselineSet(worker, provenCumulativeScore, epoch);
            emit Claimed(epoch, worker, 0, 0, provenCumulativeScore);
            return;
        }

        uint256 prev = lastClaimedCumulative[worker];
        if (provenCumulativeScore <= prev) return;
        uint256 delta = provenCumulativeScore - prev;

        // Time-based GOAT cap: maxThisClaim = capPerDay * elapsed / 1 days (mul before div).
        // Overflow-safe: if capPerDay * elapsed would overflow, treat as uncapped for this claim
        // (only possible if capPerDay is absurdly large — production uses 67e18).
        uint256 elapsed = block.timestamp - uint256(lastClaimTime[worker]);
        uint256 maxGoat;
        if (capPerDay == 0) {
            maxGoat = type(uint256).max;
        } else if (elapsed == 0) {
            maxGoat = 0;
        } else if (capPerDay > type(uint256).max / elapsed) {
            maxGoat = type(uint256).max;
        } else {
            maxGoat = (capPerDay * elapsed) / 1 days;
        }
        // rawGoat = delta * rate — also overflow-safe for huge fuzz scores.
        uint256 rawGoat;
        if (delta > 0 && b.rate > type(uint256).max / delta) {
            rawGoat = type(uint256).max;
        } else {
            rawGoat = delta * b.rate;
        }
        uint256 goatAmount = rawGoat > maxGoat ? maxGoat : rawGoat;
        // Score watermark advances only by score corresponding to minted GOAT (floor — never
        // favors worker). Remainder stays claimable next epoch (non-forfeiting).
        uint256 cappedScore = goatAmount / b.rate;
        if (cappedScore == 0) {
            // elapsed too short for 1 score unit at current rate — leave claimed unset so a
            // later claim (more elapsed) or next epoch can mint; no state change, no loop profit.
            return;
        }
        uint256 newCumulative = prev + cappedScore;
        lastClaimedCumulative[worker] = newCumulative;
        lastClaimTime[worker] = uint64(block.timestamp);
        claimed[epoch][worker] = true;

        uint256 hb = goatAmount * holdbackBps / 10_000;
        uint256 liquid = goatAmount - hb;
        uint256 fee;
        if (keeperFee > 0 && liquid > 0) {
            fee = liquid > keeperFee ? keeperFee : liquid;
            liquid -= fee;
            goat.mint(msg.sender, fee);
            emit KeeperFeePaid(epoch, worker, msg.sender, fee);
        }
        if (liquid > 0) goat.mint(worker, liquid);
        if (hb > 0) {
            goat.mint(address(escrow), hb);
            escrow.credit(bytes32(epoch), worker, hb, uint64(block.timestamp) + holdbackBackstop);
        }
        emit Claimed(epoch, worker, liquid, hb, newCumulative);
    }
}
