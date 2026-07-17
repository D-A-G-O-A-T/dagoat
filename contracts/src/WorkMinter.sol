// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GoatCoin} from "./GoatCoin.sol";
import {HoldbackEscrow} from "./HoldbackEscrow.sol";

/// Free-market mint core (spec §2, Season-0 full-system design, task S1).
/// Successor to JobVault for v2: verified work units mint GOAT directly —
/// no USDT anywhere in this contract, no escrow pull, no desk transfer, no
/// budget cap. Mint = units[i] x unitReward per worker, split holdbackBps
/// to HoldbackEscrow (worker property, spec S1.3) with the remainder
/// liquid via GoatCoin.mint. This IS the free-market mint law: verified
/// work mints GOAT, unconstrained by anyone's USDT. JobVault remains
/// in-repo, untouched, as the retired Season-0 backed pilot.
contract WorkMinter {
    error NotSafe();
    error JobExists();
    error JobUnknown();
    error JobClosed();
    error InvalidHoldback();
    error InvalidUnitReward();
    error FounderAcceptRequired();
    error LengthMismatch();
    error HoldbackOpen();
    error ManifestReplayed();

    uint64 public constant BACKSTOP = 30 days;

    address public immutable safe;
    GoatCoin public immutable goat;
    HoldbackEscrow public immutable escrow;

    struct Job {
        bytes32 catalogHash;
        uint256 unitReward; // GOAT wei per verified work unit, per-job constant
        uint256 minted; // GOAT wei
        uint16 holdbackBps;
        address externalAcceptor;
        bool founderAcceptOnly;
        bool closed;
        uint64 lastMint;
    }

    // unitReward == 0 is the "does not exist" sentinel: createJob requires
    // unitReward > 0, so no created job can ever read back as zero here.
    mapping(bytes32 => Job) public jobs;
    // Replay guard: a manifestRoot can be minted at most once, globally.
    // Prevents re-submitting the same signed-off work manifest twice.
    mapping(bytes32 => bool) public usedManifest;

    event JobCreated(
        bytes32 indexed jobId,
        bytes32 catalogHash,
        uint256 unitReward,
        uint16 holdbackBps,
        address externalAcceptor,
        bool founderAcceptOnly
    );
    event MintBatch(bytes32 indexed jobId, bytes32 manifestRoot, uint256 totalUnits, uint256 totalGoat);
    event JobClosedEvent(bytes32 indexed jobId);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(address safe_, GoatCoin goat_, HoldbackEscrow escrow_) {
        safe = safe_;
        goat = goat_;
        escrow = escrow_;
    }

    function createJob(
        bytes32 jobId,
        bytes32 catalogHash,
        uint256 unitReward,
        uint16 holdbackBps,
        address externalAcceptor,
        bool founderAcceptOnly
    ) external onlySafe {
        if (jobs[jobId].unitReward != 0) revert JobExists();
        if (unitReward == 0) revert InvalidUnitReward();
        if (holdbackBps > 10_000) revert InvalidHoldback();
        // founderAcceptOnly replaces v1's `rehearsal` flag (renamed for
        // honesty: the science is real; only the acceptance is
        // founder-only). No external acceptor lined up => must be
        // explicitly labeled founder-accept-only.
        if (externalAcceptor == address(0) && !founderAcceptOnly) revert FounderAcceptRequired();
        jobs[jobId] = Job({
            catalogHash: catalogHash,
            unitReward: unitReward,
            minted: 0,
            holdbackBps: holdbackBps,
            externalAcceptor: externalAcceptor,
            founderAcceptOnly: founderAcceptOnly,
            closed: false,
            lastMint: 0
        });
        emit JobCreated(jobId, catalogHash, unitReward, holdbackBps, externalAcceptor, founderAcceptOnly);
    }

    function mintBatch(bytes32 jobId, bytes32 manifestRoot, address[] calldata workers, uint256[] calldata units)
        external
        onlySafe
    {
        Job storage job = jobs[jobId];
        if (job.unitReward == 0) revert JobUnknown();
        if (job.closed) revert JobClosed();
        if (workers.length != units.length) revert LengthMismatch();
        if (usedManifest[manifestRoot]) revert ManifestReplayed();
        usedManifest[manifestRoot] = true;

        uint256 totalUnits;
        uint256 totalGoat;
        uint64 deadline = uint64(block.timestamp) + BACKSTOP;
        for (uint256 i = 0; i < workers.length; i++) {
            uint256 goatAmount = units[i] * job.unitReward;
            totalUnits += units[i];
            totalGoat += goatAmount;
            uint256 hb = goatAmount * job.holdbackBps / 10_000;
            uint256 liquid = goatAmount - hb;
            if (liquid > 0) goat.mint(workers[i], liquid);
            if (hb > 0) {
                goat.mint(address(escrow), hb);
                escrow.credit(jobId, workers[i], hb, deadline);
            }
        }
        job.minted += totalGoat;
        job.lastMint = uint64(block.timestamp);
        emit MintBatch(jobId, manifestRoot, totalUnits, totalGoat);
    }

    function closeJob(bytes32 jobId) external onlySafe {
        Job storage job = jobs[jobId];
        if (job.unitReward == 0) revert JobUnknown();
        if (job.closed) revert JobClosed();
        // Close only after the holdback question is settled: released, or
        // past the backstop deadline, or nothing was ever minted.
        if (job.minted > 0 && !escrow.jobReleased(jobId) && block.timestamp <= escrow.jobDeadline(jobId)) {
            revert HoldbackOpen();
        }
        job.closed = true;
        emit JobClosedEvent(jobId);
    }
}
