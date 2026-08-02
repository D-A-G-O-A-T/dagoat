// Every user-facing bandwidth string except the disclosure itself, which lives in
// `policy.v1.json` -- the single artifact the daemon hashes -- and is swept from there.
//
// HONESTY POSTURE. Exactly one [NOW] claim exists on this surface and it is about
// refusal: the signed-record gate and the destination allowlist refuse today, and
// refusing is not a capability. Nothing here has crossed a real network, there is no
// public gateway, and no settlement contract is deployed on any network.
//
// Design authority: the "The No-Ponzi Invariant — GoatCoin's load-bearing economic
// rule" spec, §1 and §8.

export const BANDWIDTH_TAB_LABEL = "Bandwidth";

export const PROXY_TARGET_POSTURE =
  "[TARGET] Sharing bandwidth is a design target, not a deployed capability. There is no public " +
  "gateway to connect to, nobody is buying fetches, and no settlement contract is deployed on any " +
  "network. What runs today is the refusal path.";

export const PROXY_REFUSAL_NOW_NOTE =
  "[NOW] The signed-record gate and the destination allowlist refuse today. Refusing is not a capability.";

export const PROXY_PAYOUT_NOTE =
  "[TARGET] Any future operator payout is a transfer of GOAT that already exists. No GOAT is created " +
  "by moving bytes, and the protocol does not promise a buyer for it.";

// The three notes above are all true and still leave an operator believing a 90/10
// "revenue split" hands them 90% of what a consumer paid. It does not.
export const PROXY_SPLIT_PROVENANCE_NOTE =
  "[TARGET] No consumer payment is distributed to operators. The 90/10 split divides a pool of GOAT " +
  "the funder deposited in advance; how large that pool is, is a governance decision, not a share of " +
  "what anyone paid.";

export const PROXY_MARKETPLACE_GATE_NOTE =
  "[RESEARCH] An open market where anyone can buy fetches is not part of this build and is not " +
  "scheduled. It stays shut until the five criteria named in the design are met and published.";

export const PROXY_SWITCH_LABEL = "Share bandwidth";
export const PROXY_SWITCH_CAPTION =
  "Off unless you have signed the disclosure. Signing needs your wallet unlocked.";

export const PROXY_CONSENT_TITLE = "Read this before sharing your connection";
export const PROXY_CONSENT_SCROLL_HINT = "Read to the end of the text to enable the sign button.";
export const PROXY_CONSENT_SIGN_HELP =
  "Signing records the exact text you read, the destination list, today's date, your daily and speed " +
  "limits, and your wallet. It is not a transaction and cannot move anything.";

export const PROXY_CONSENT_ABSENT_NOTE =
  "Nothing is signed yet, so nothing can leave your connection through this feature.";
export const PROXY_CONSENT_EXPIRED_NOTE =
  "Your signed record passed its 90-day limit. Traffic is stopped until you read the disclosure again and sign.";
export const PROXY_CONSENT_STALE_NOTE =
  "The disclosure text or the destination list changed since you signed. Traffic is stopped until you read the new text and sign again.";
export const PROXY_CONSENT_WALLET_MISMATCH_NOTE =
  "The signed record belongs to a different wallet. Switch back to that wallet, or sign again with this one.";
export const PROXY_CONSENT_WALLET_UNKNOWN_NOTE =
  "No wallet is active, so the stored record cannot be tied to an owner. Unlock a wallet to continue.";
export const PROXY_CONSENT_NOT_YET_VALID_NOTE =
  "The stored record is dated in the future. Check this machine's clock, then sign again.";
export const PROXY_CONSENT_BAD_SIGNATURE_NOTE =
  "The stored record does not check out against its own text. It has been ignored. Sign again to continue.";
export const PROXY_CONSENT_MALFORMED_NOTE =
  "The stored record cannot be read. It has been ignored. Sign again to continue.";
export const PROXY_POLICY_MISMATCH_NOTE =
  "This screen and the background process disagree about the disclosure text. Signing is blocked until the app is reinstalled.";
export const PROXY_WALLET_LOCKED_NOTE = "Unlock your wallet to sign the disclosure.";
export const PROXY_SIGN_REFUSED_NOTE = "Nothing was signed and nothing was stored. The switch stayed off.";

export const PROXY_ALLOWLIST_TITLE = "Destinations that can be reached";
export const PROXY_ALLOWLIST_NOTE =
  "This is the whole list. Anything not on it is refused before a socket opens, including addresses inside your own home network.";

export const PROXY_CAP_LABEL = "Daily limit";
export const PROXY_THROTTLE_LABEL = "Speed limit";
export const PROXY_SCHEDULE_LABEL = "Active hours";
export const PROXY_CAPS_ENFORCEMENT_NOTE =
  "Held by the background process. These stay in force if this window is closed or killed.";
// The ceiling and the speed limit are inside the bytes you signed, so this window can
// lower them and cannot raise them. Saying so is the difference between a control and
// a suggestion.
export const PROXY_CAPS_CONSENTED_NOTE =
  "Your signed record names the daily and speed limits you agreed to. Lowering them here takes effect at once; raising them past what you signed does not, until you read the disclosure again and sign.";
export const PROXY_SCHEDULE_EMPTY_NOTE = "No hours set means any hour is allowed.";

export const PROXY_KILL_LABEL = "Stop all traffic now";
export const PROXY_KILL_SUBTEXT =
  "Ends requests in flight and closes every socket within five seconds. Your signed record is kept, so you can start again without signing.";
export const PROXY_REVOKE_LABEL = "Withdraw consent";
export const PROXY_REVOKE_SUBTEXT =
  "Stops traffic and deletes the signed record. Turning it back on means reading the disclosure and signing again.";
export const PROXY_HALT_RECEIPT_LABEL = "Stopped. Open sockets:";
export const PROXY_HALT_UNVERIFIED_NOTE =
  "not confirmed -- the background process did not report back in time, so it was forced to close.";

export const PROXY_STATUS_TITLE = "This machine";
export const PROXY_BYTES_TODAY_LABEL = "Sent and received today";
export const PROXY_BYTES_SESSION_LABEL = "Since this window opened";
export const PROXY_SOCKETS_LABEL = "Connections open";
export const PROXY_COUNTER_SOURCE_NOTE =
  "These figures belong to the background process, not to this window, and a closed window does not reset them.";
// "Not observed" is not "zero". A screen that prints 0 for a number nobody read is a
// screen that reports a clean machine it never checked -- the same failure the halt
// receipt refuses when it says Unverified instead of 0.
export const PROXY_COUNTER_UNOBSERVED = "not observed";

export const PROXY_EGRESS_LOG_TITLE = "Destinations contacted";
export const PROXY_EGRESS_EMPTY = "Nothing has been contacted.";
export const PROXY_EGRESS_UNOBSERVED =
  "This build does not read the background process's destination stream, so this is not a record of nothing happening -- it is no record at all.";
export const PROXY_EGRESS_GAP_NOTE =
  "Some entries missed the live feed and were re-read from the background process.";
export const PROXY_EGRESS_PRIVACY_NOTE =
  "Only the list entry, the address it resolved to, and byte counts are kept. No page contents, paths, or search terms.";
export const PROXY_SEQUENCE_BROKEN_NOTE =
  "The background process's numbering skipped. Entries may be missing from this list.";

export const PROXY_UNAVAILABLE_NOTE =
  "The background process for this feature is not installed in this build.";

export const PROXY_ALL_COPY = [
  BANDWIDTH_TAB_LABEL, PROXY_TARGET_POSTURE, PROXY_REFUSAL_NOW_NOTE, PROXY_PAYOUT_NOTE,
  PROXY_SPLIT_PROVENANCE_NOTE, PROXY_HALT_UNVERIFIED_NOTE,
  PROXY_MARKETPLACE_GATE_NOTE, PROXY_SWITCH_LABEL, PROXY_SWITCH_CAPTION, PROXY_CONSENT_TITLE,
  PROXY_CONSENT_SCROLL_HINT, PROXY_CONSENT_SIGN_HELP, PROXY_CONSENT_ABSENT_NOTE,
  PROXY_CONSENT_EXPIRED_NOTE, PROXY_CONSENT_STALE_NOTE, PROXY_CONSENT_WALLET_MISMATCH_NOTE,
  PROXY_CONSENT_WALLET_UNKNOWN_NOTE, PROXY_CONSENT_NOT_YET_VALID_NOTE,
  PROXY_CONSENT_BAD_SIGNATURE_NOTE, PROXY_CONSENT_MALFORMED_NOTE, PROXY_POLICY_MISMATCH_NOTE,
  PROXY_WALLET_LOCKED_NOTE, PROXY_SIGN_REFUSED_NOTE, PROXY_ALLOWLIST_TITLE, PROXY_ALLOWLIST_NOTE,
  PROXY_CAP_LABEL, PROXY_THROTTLE_LABEL, PROXY_SCHEDULE_LABEL, PROXY_CAPS_ENFORCEMENT_NOTE,
  PROXY_CAPS_CONSENTED_NOTE,
  PROXY_SCHEDULE_EMPTY_NOTE, PROXY_KILL_LABEL, PROXY_KILL_SUBTEXT, PROXY_REVOKE_LABEL,
  PROXY_REVOKE_SUBTEXT, PROXY_HALT_RECEIPT_LABEL, PROXY_STATUS_TITLE, PROXY_BYTES_TODAY_LABEL,
  PROXY_BYTES_SESSION_LABEL, PROXY_SOCKETS_LABEL, PROXY_COUNTER_SOURCE_NOTE,
  PROXY_COUNTER_UNOBSERVED,
  PROXY_EGRESS_LOG_TITLE, PROXY_EGRESS_EMPTY, PROXY_EGRESS_UNOBSERVED, PROXY_EGRESS_GAP_NOTE,
  PROXY_EGRESS_PRIVACY_NOTE, PROXY_SEQUENCE_BROKEN_NOTE,
  PROXY_UNAVAILABLE_NOTE,
];
