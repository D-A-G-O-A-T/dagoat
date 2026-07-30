# GoatAPP Patch Notes

All notable changes to the GoatAPP desktop app are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows
[Semantic Versioning](https://semver.org/), pre-1.0 while GoatAPP is on testnet: `0.MINOR.PATCH`
— PATCH for fixes/small changes, MINOR for features/notable behavior changes, staying `0.x` until
mainnet launch (`1.0.0`). See
the "PATCHNOTES.md Convention — Notice to Consultant + Advisor" notice for the rule that every change
lands an entry here before it's considered done, and for how versions are cut.

---

## [Unreleased]

### Added

- Gas-drip relayer endpoint (`POST /v1/relay/gas-drip` on the attestor) and a matching desktop sell
  preflight (`desktop/src/chain/gasDrip.js`, `ensureGasForSell` in `Market.jsx`): before an
  approve/sell, the wallet's ETH balance is checked against an estimated gas cost, and if short, a
  rate-limited testnet-ETH top-up is requested and polled for before the transaction proceeds. The
  endpoint requires `GOAT_COIN_ADDRESS` to be configured (otherwise it stays disabled) and enforces
  one drip per wallet per UTC calendar day by default.
- Version tag in the honesty footer (`v0.1.0 · testnet`, from the new `desktop/src/version.js`) so
  testers can cite a build number when reporting bugs.
- CI now runs `cargo test` for `tools/goat-attestor` and `npm test` (vitest) for `desktop`, alongside
  the existing root-spine and contracts jobs.

### Changed

### Fixed

- Copy-law pass over Market copy: user-facing strings that read as present-tense earning
  promises (`Market.jsx`'s sell-proceeds note and donor-faucet note, plus `market.js`'s
  `HOLD_NOTICE_COPY`) now describe GOAT as minted for verified public-good work instead of
  "earned," and the enrollment-prompt copy (`ENROLLMENT_WARNING_COPY`, the `TransferRestricted`
  error, `AlreadyHasDesk`, `NOT_EXCHANGE_COPY`, and the Wallet tab's "no wallet unlocked" message)
  no longer makes positional claims ("above"/"below") about where a button or panel sits on the
  page, so the copy stays accurate regardless of layout order.
- Documentation-accuracy pass over the gas-drip design doc and code comments: corrected a
  `gas_drips.rs` comment that overstated Windows file-rename atomicity, retagged the still-unbuilt
  global drip budget (G8) as planned rather than implemented, brought every section of the design
  doc in line with the implemented reserve-before-send quota model (no more sections describing
  the superseded release-on-failure behavior), corrected a stale per-wallet cap figure and a
  nonexistent env var name, corrected an "optional" balance check that's actually required to
  enable the endpoint at all, and fixed a dead cross-reference to the patch-notes convention
  notice.

### Security

- The attestor's native ETH transfer (used to send gas drips) now pins an explicit gas limit on the
  send instead of relying on `eth_estimateGas`, so a recipient contract can't force the relayer to
  spend far more gas than a plain transfer requires.

---

## [0.1.0] — 2026-07-19

Baseline testnet build. This is a summary of the major systems present at this snapshot, not a
reconstructed session log.

### Added

- **Onboarding wizard** — a six-step first-run flow (disclaimer → wallet create / import / opt-out
  → key reveal) in the cozy-dark glass UI theme.
- **Wallet ↔ FAH identity binding** — per-wallet FAH profiles; on a naming conflict between the
  wallet and the FAH client, the on-chain enrollment wins; Start is fail-closed (it refuses to
  fold under a name the active wallet doesn't hold rather than mis-crediting); a finish-mode gate
  handles switching the active wallet while a run is finishing; a mid-run identity guard rechecks
  live identity while folding; overriding the FAH account from outside the app automatically
  unlinks it from the wallet; the FAH client is stopped when the app closes.
- **Work-crediting and mint pipeline** — Folding@home work is proposed to the attestor, confirmed,
  and finalized per epoch; per-wallet username baselines track already-credited work so switching
  identities doesn't double-count; finalized epochs mint GOAT on testnet.
- **Market** — buy desks for acquiring GOAT, plus a gasless sell path backed by a rate-limited gas
  drip (one gasless sell per wallet per UTC calendar day, resetting at 00:00 UTC).
- **Wallet storage** — the local wallet is Stronghold-encrypted; the private key is masked by
  default and shown only on explicit user action (at creation, or on demand from a masked row in
  the Wallet tab while unlocked); it is never logged and never persisted on the JavaScript side.

This is a description of what the software does on testnet, not a promise of value — GOAT under
this build is a pilot token; see the in-app honesty banner for the current standing terms.
