import { keccak256, stringToBytes } from "viem";

// Season-0's single FAH job id, per Global Constraints (docs/superpowers/plans/
// 2026-07-11-season0-fullsystem.md) and design §7: Ops creates this job once
// against WorkMinter.createJob; Wallet reads escrow.holdbackOf(jobId, addr)
// for it. Kept as one shared constant so Wallet/Ops/Miner never diverge.
export const SEASON0_FAH_JOB_ID_STR = "season0-fah";
export const SEASON0_FAH_JOB_ID = keccak256(stringToBytes(SEASON0_FAH_JOB_ID_STR));

// Published mint formula (design §4) — shown verbatim in the Wallet footer.
export const WORK_UNIT_FORMULA =
  "1 credited Folding@home work unit (WU) = 1 work unit = 1 GOAT";

// The only catalog entry active in Season 0; MintBatch logs don't carry a
// human-readable label on-chain, so provenance rows use this static string.
export const FAH_CATALOG_LABEL = "Folding@home — public biomedical research";
