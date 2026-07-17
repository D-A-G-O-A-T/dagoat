// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {GoatCoin} from "./GoatCoin.sol";
import {HoldbackEscrow} from "./HoldbackEscrow.sol";

/// Per-job USDT escrow + the only GOAT mint path (spec §2.3).
/// THE No-Ponzi enforcement point: GOAT cannot mint beyond deposited
/// USDT at RATE, and matching USDT moves to the RedemptionDesk at mint
/// time so the desk is solvent by construction. Season instancing:
/// deploy one vault per season; Season 0 funder is the founder wallet.
contract JobVault {
    using SafeERC20 for IERC20;

    error NotSafe();
    error JobExists();
    error JobUnknown();
    error JobClosed();
    error RehearsalRequired();
    error MintExceedsEscrow();
    error LengthMismatch();
    error HoldbackOpen();
    error InvalidHoldback();

    /// USDT (6dp) units per 1e18 GOAT wei: 1 GOAT = 0.01 USDT.
    uint256 public constant RATE = 10_000;
    uint64 public constant BACKSTOP = 30 days;

    address public immutable safe;
    IERC20 public immutable usdt;
    GoatCoin public immutable goat;
    HoldbackEscrow public immutable escrow;
    address public immutable desk;

    struct Job {
        bytes32 catalogHash;
        address funder;
        uint256 contributorBudgetUsdt; // 6dp
        uint256 minted; // GOAT wei
        uint16 holdbackBps;
        address externalAcceptor;
        bool rehearsal;
        bool closed;
        uint64 lastMint;
    }

    mapping(bytes32 => Job) public jobs;

    /// Cumulative USDT moved to the desk per job (ceiling of minted value,
    /// so the desk is solvent by construction across batches and jobs).
    mapping(bytes32 => uint256) public usdtFunded;

    event JobCreated(
        bytes32 indexed jobId,
        bytes32 catalogHash,
        address indexed funder,
        uint256 budget,
        address externalAcceptor,
        bool rehearsal
    );
    event MintBatch(bytes32 indexed jobId, bytes32 manifestRoot, uint256 totalGoat, uint256 usdtToDesk);
    event JobClosedEvent(bytes32 indexed jobId, uint256 refund);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(address safe_, IERC20 usdt_, GoatCoin goat_, HoldbackEscrow escrow_, address desk_) {
        safe = safe_;
        usdt = usdt_;
        goat = goat_;
        escrow = escrow_;
        desk = desk_;
    }

    function usdtValue(uint256 goatAmount) public pure returns (uint256) {
        return goatAmount * RATE / 1e18;
    }

    function usdtValueCeil(uint256 goatAmount) public pure returns (uint256) {
        return (goatAmount * RATE + 1e18 - 1) / 1e18;
    }

    function createJob(
        bytes32 jobId,
        bytes32 catalogHash,
        address funder,
        uint256 contributorBudgetUsdt,
        uint16 holdbackBps,
        address externalAcceptor,
        bool rehearsal
    ) external onlySafe {
        if (jobs[jobId].funder != address(0)) revert JobExists();
        // Founder amendment 3 / S2.2: no external acceptor => must be
        // explicitly labeled a rehearsal (mechanism test, not demand proof).
        if (externalAcceptor == address(0) && !rehearsal) revert RehearsalRequired();
        if (holdbackBps > 10_000) revert InvalidHoldback();
        jobs[jobId] = Job({
            catalogHash: catalogHash,
            funder: funder,
            contributorBudgetUsdt: contributorBudgetUsdt,
            minted: 0,
            holdbackBps: holdbackBps,
            externalAcceptor: externalAcceptor,
            rehearsal: rehearsal,
            closed: false,
            lastMint: 0
        });
        usdt.safeTransferFrom(funder, address(this), contributorBudgetUsdt);
        emit JobCreated(jobId, catalogHash, funder, contributorBudgetUsdt, externalAcceptor, rehearsal);
    }

    function mintBatch(bytes32 jobId, bytes32 manifestRoot, address[] calldata workers, uint256[] calldata amounts)
        external
        onlySafe
    {
        Job storage job = jobs[jobId];
        if (job.funder == address(0)) revert JobUnknown();
        if (job.closed) revert JobClosed();
        if (workers.length != amounts.length) revert LengthMismatch();

        uint256 total;
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];
        }
        // The invariant: mint cannot outrun escrow (No-Ponzi, spec §2.3).
        // Ceiling-valued so cumulative desk funding never exceeds budget.
        uint256 fundedAfter = usdtValueCeil(job.minted + total);
        if (fundedAfter > job.contributorBudgetUsdt) revert MintExceedsEscrow();

        uint64 deadline = uint64(block.timestamp) + BACKSTOP;
        for (uint256 i = 0; i < workers.length; i++) {
            uint256 hb = amounts[i] * job.holdbackBps / 10_000;
            uint256 liquid = amounts[i] - hb;
            goat.mint(workers[i], liquid);
            if (hb > 0) {
                goat.mint(address(escrow), hb);
                escrow.credit(jobId, workers[i], hb, deadline);
            }
        }
        job.minted += total;
        job.lastMint = uint64(block.timestamp);
        // Sum of per-batch floors under-funds the desk across batches and
        // jobs (fuzz-found solvency leak); cumulative ceilings provably
        // cover every worker redemption while staying within the budget.
        uint256 backing = fundedAfter - usdtFunded[jobId];
        usdtFunded[jobId] = fundedAfter;
        usdt.safeTransfer(desk, backing);
        emit MintBatch(jobId, manifestRoot, total, backing);
    }

    function closeJob(bytes32 jobId) external onlySafe {
        Job storage job = jobs[jobId];
        if (job.funder == address(0)) revert JobUnknown();
        if (job.closed) revert JobClosed();
        // Close only after the holdback question is settled: released, or
        // past the backstop deadline, or nothing was ever minted.
        if (job.minted > 0 && !escrow.jobReleased(jobId) && block.timestamp <= escrow.jobDeadline(jobId)) {
            revert HoldbackOpen();
        }
        job.closed = true;
        uint256 refund = job.contributorBudgetUsdt - usdtFunded[jobId];
        if (refund > 0) usdt.safeTransfer(job.funder, refund);
        emit JobClosedEvent(jobId, refund);
    }
}
