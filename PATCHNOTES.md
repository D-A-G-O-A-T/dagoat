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
- Off-chain verification engine for the allowlisted fetch network (`tools/goat-attestor/src/proxy/`): a
  three-signature receipt — the consumer signs what was asked for, the node signs what it delivered, and the
  relay countersigns what it actually observed — checked by a ten-stage pipeline that refuses any
  disagreement between the node's claim and the relay's measurement exactly, with no tolerance. A receipt
  carries byte counts and a destination-list entry number only: no address, path or content of any request
  is recorded anywhere, and a test fails the build if such a column is ever added. The lane is off by
  default and its endpoints do not respond while it is off. No user-visible change to the app.
- A holding contract for the fetch network's revenue path, deliberately inert: it cannot move anything until
  a one-way switch is thrown, and that switch has no reverse. Nothing is deployed anywhere public.
- Settlement contracts for the allowlisted fetch network (`contracts/src/proxy/`): a revenue settlement
  that moves GOAT which already exists — it holds no minter role and has no path to one — and a consumer
  registry with no public registration door. Payouts are bounded on chain by what was actually deposited,
  as a contract-level rule rather than a policy: the contract cannot pay out more than it holds. There is
  no burn mechanism anywhere on this path, asserted three ways (compiled runtime, published interface, and
  source). Nothing here is deployed anywhere public, and no user-visible change reaches the app yet.
- CI now type-checks the desktop app's Rust shell (`cargo check --locked --all-targets` over
  `desktop/src-tauri`, with the GTK/WebKit system libraries and a built frontend that `tauri-build`
  requires). Until now nothing in CI compiled that crate at all, so the Rust behind the IPC bridge —
  wallet handling and the work-backend adapter — could break on a remote runner without any job going
  red, while the JavaScript half was gated by vitest. No user-visible change to the app; this closes a
  gap in what CI can catch before a build reaches testers.
- Added the transport layer for the allowlisted fetch network: a home node connects
  outward to the gateway over TLS on port 443 and never opens a port of its own, so it
  works behind home routers and carrier NAT without any setup. All GOAT authentication
  inside that connection uses post-quantum cryptography; the connection carries an
  operator's bandwidth caps and a one-way stop switch that keeps working even if the
  app window is closed. Nothing in this layer creates or destroys GOAT.
- CI now gates that transport layer in **both** of its build configurations. The layer has a
  relay-side scheduling component that is compiled out of the home-node build on purpose, and
  four of its tests live behind that switch; a single test run would have left them existing
  but never executing anywhere. The suite and the linter each run twice. No user-visible change
  to the app.
- Added a separate background program for the allowlisted fetch network. It only ever
  contacts a short, fixed list of public research-metadata addresses, it never opens a
  port on your machine, and it stops within five seconds when you switch it off. It runs
  only while a program you started is telling it to, and it starts nothing by itself: it
  registers no startup entry, no background service and no scheduled task, and it goes
  away when the app does. Nothing here creates or destroys GOAT, and nothing about it is
  switched on for anyone yet.
- A Bandwidth screen, hidden unless the background process for it is installed in your build.
  Sharing your connection stays off until you read a separate disclosure and sign it with your
  wallet; the signed record names the exact text and destination list you read, your daily and
  speed limits, and the date, and it expires after 90 days. The disclosure states plainly that
  websites see your home address, that your internet provider may cancel your account, that your
  whole household may be locked out of ordinary sites with repeated CAPTCHAs that can outlast
  uninstalling, and that police may contact whoever pays for the line. Nothing on this screen is
  a promise of payment.
- Daily limit, speed limit and active hours for bandwidth sharing, held by the background process
  so they stay in force when the window is closed or killed. The limits you sign are the maximum:
  the screen can lower them at once, and cannot raise them past what you signed without you reading
  the disclosure and signing again.
- The full destination list is shown on screen, and a control that stops all traffic and closes
  every socket within five seconds while keeping your signed record, so starting again does not
  mean signing again.
- Counters and the list of destinations contacted say "not observed" rather than showing zero when
  this build is not reading the background process's own figures. A zero nobody measured reads as a
  clean machine that was never checked.
- CI now gates that background program: its linter, its formatter and its full test suite.
  The suite runs on a single thread on purpose, because the check that proves the stop
  switch really closed the connections reads the operating system's own list of open
  connections for the whole program, and other tests opening and closing connections at
  the same time would turn that check into a coin flip. Widening the tolerance until the
  flake stops would have been the wrong fix. No user-visible change to the app.

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
- The fetch network's background program refuses to start at all unless a signed consent
  record matches the exact disclosure text and the exact destination list currently
  installed, and names the wallet the app said is active. There is no reduced-capability
  start: every one of those checks failing is a program that does not run.
- Requests are checked against the address a name actually resolves to, that address is
  fixed for the life of the connection, and addresses inside your own home network are
  always refused. Every redirect is re-checked from scratch.
- No page contents, paths or search terms are written to any log, record or file. The live
  list on screen shows the list entry contacted, the address it resolved to, and byte
  counts, and nothing more; that list holds the most recent 512 entries in memory and is
  never written to disk. The payment records the protocol keeps carry only a list-entry
  number and byte counts.
- When you switch the program off, the number of connections it reports as still open is
  read back from the operating system, not from the program's own bookkeeping. If that
  reading cannot be taken, the result is reported as unverified rather than as zero — a
  zero nobody measured reads as "clean" and would be the one number that can never fail.
- The app also checks the signed record before it writes it and before it starts anything, and
  the wallet it checks against is the one the app itself holds unlocked — never one the screen
  names. A check whose expected answer the caller supplies is a check every forged record passes.
  A record whose owner cannot be established is refused, not treated as valid.
- A record that has been edited without being re-signed is reported as a bad signature, not as a
  changed disclosure. Reporting tampering as a benign version change is how somebody is talked
  into signing again.
- Your daily limit and speed limit are part of what you sign, so editing the file that holds them
  cannot raise them: the amount enforced is the smaller of what you signed and what is configured.
  Turning the switch on is a request, not permission — it is refused unless the signed record
  verifies at that moment.
- The app will not start the background program unless that program's fingerprint matches the one
  the build recorded. A build that recorded no fingerprint starts nothing at all, rather than
  starting whatever it finds.
- Bandwidth settings are kept in files the background process owns, never in the store the app's
  own window can write. Those files are read back and re-checked on every read, so hand-editing
  one cannot raise a limit.
- CI now type-checks, lints and RUNS the Rust behind the app's window. Until this change nothing
  in CI executed a single assertion there.

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
