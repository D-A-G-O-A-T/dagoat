export function isTestnetWithMockUsdt(networkId) {
  const id = Number(networkId);
  return id === 31337 || id === 84532;
}

export function isFounderWallet(address, safeAddress) {
  if (!address || !safeAddress) return false;
  return String(address).toLowerCase() === String(safeAddress).toLowerCase();
}

/**
 * Ops tab is founder-only (EnrollmentRegistry.safe).
 * Enrolled workers (Rookie, etc.) must not see Ops — enroll is permissionless
 * for workers via enrollSelf / gasless relayer; Ops is roster + founder tools.
 * `enrolled` is accepted for call-site stability but ignored.
 */
export function canSeeOpsTab({ isFounder }) {
  return Boolean(isFounder);
}

/** @param {{who: string, status: boolean}[]} logs chronological */
export function reduceEnrolledLogs(logs) {
  const map = new Map();
  for (const row of logs) {
    if (!row?.who) continue;
    map.set(String(row.who).toLowerCase(), Boolean(row.status));
  }
  return [...map.entries()].filter(([, ok]) => ok).map(([addr]) => addr);
}
