// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GoatCoin} from "./GoatCoin.sol";

/// Per-job, per-worker holdback (spec §2.4). Holdback is the WORKER'S
/// property (founder amendment 2): released at final acceptance, or by
/// anyone after the backstop deadline (S2/S4 sponsor-refusal backstop).
/// Slashes transfer to the reserve — never burned, never to challengers
/// (S1.3). Worker lists are bounded by pilot cohort size (N ≤ ~15/batch).
contract HoldbackEscrow {
    error NotSafe();
    error NotVault();
    error VaultAlreadySet();
    error AlreadyReleased();
    error DeadlineNotReached();
    error InsufficientHoldback();
    error NothingCredited();

    address public immutable safe;
    GoatCoin public immutable goat;
    address public immutable reserve;
    address public vault;

    struct JobState {
        uint64 deadline;
        bool released;
        address[] workers;
        mapping(address => uint256) balances;
        mapping(address => bool) seen;
    }

    mapping(bytes32 => JobState) private jobs;

    event Credited(bytes32 indexed jobId, address indexed worker, uint256 amount, uint64 deadline);
    event Released(bytes32 indexed jobId, bool viaBackstop);
    event Slashed(bytes32 indexed jobId, address indexed worker, uint256 amount, bytes32 reasonHash);

    modifier onlySafe() {
        if (msg.sender != safe) revert NotSafe();
        _;
    }

    constructor(address safe_, GoatCoin goat_, address reserve_) {
        safe = safe_;
        goat = goat_;
        reserve = reserve_;
    }

    function setVault(address vault_) external onlySafe {
        if (vault != address(0)) revert VaultAlreadySet();
        vault = vault_;
    }

    function credit(bytes32 jobId, address worker, uint256 amount, uint64 backstopDeadline_) external {
        if (msg.sender != vault) revert NotVault();
        JobState storage j = jobs[jobId];
        if (j.released) revert AlreadyReleased();
        if (!j.seen[worker]) {
            j.seen[worker] = true;
            j.workers.push(worker);
        }
        j.balances[worker] += amount;
        if (backstopDeadline_ > j.deadline) j.deadline = backstopDeadline_;
        emit Credited(jobId, worker, amount, j.deadline);
    }

    function release(bytes32 jobId) external onlySafe {
        _release(jobId, false);
    }

    function releaseAfterDeadline(bytes32 jobId) external {
        JobState storage j = jobs[jobId];
        if (block.timestamp <= j.deadline) revert DeadlineNotReached();
        _release(jobId, true);
    }

    function slash(bytes32 jobId, address worker, uint256 amount, bytes32 reasonHash) external onlySafe {
        JobState storage j = jobs[jobId];
        if (j.released) revert AlreadyReleased();
        if (j.balances[worker] < amount) revert InsufficientHoldback();
        j.balances[worker] -= amount;
        goat.transfer(reserve, amount);
        emit Slashed(jobId, worker, amount, reasonHash);
    }

    function holdbackOf(bytes32 jobId, address worker) external view returns (uint256) {
        return jobs[jobId].balances[worker];
    }

    function jobDeadline(bytes32 jobId) external view returns (uint64) {
        return jobs[jobId].deadline;
    }

    function jobReleased(bytes32 jobId) external view returns (bool) {
        return jobs[jobId].released;
    }

    function _release(bytes32 jobId, bool viaBackstop) internal {
        JobState storage j = jobs[jobId];
        if (j.released) revert AlreadyReleased();
        if (j.workers.length == 0) revert NothingCredited();
        j.released = true;
        for (uint256 i = 0; i < j.workers.length; i++) {
            address w = j.workers[i];
            uint256 bal = j.balances[w];
            if (bal > 0) {
                j.balances[w] = 0;
                goat.transfer(w, bal);
            }
        }
        emit Released(jobId, viaBackstop);
    }
}
