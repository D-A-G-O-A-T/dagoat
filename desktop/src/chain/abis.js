// Hand-trimmed ABIs — only the functions/events/errors the desktop UI
// actually calls or decodes. Full forge artifacts live in contracts/out/
// (e.g. contracts/out/WorkMinter.sol/WorkMinter.json); this file is a
// reviewed, minimal surface onto the v2 free-market contracts
// (contracts/src/{GoatCoin,EnrollmentRegistry,HoldbackEscrow,WorkMinter,
// BuyDesk}.sol) plus the MockUSDT test token. Keep in sync by hand — do not
// import the full forge artifacts into the bundle.

export const GOAT_COIN_ABI = [
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "totalSupply",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    type: "function",
    name: "allowance",
    stateMutability: "view",
    inputs: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "transfer",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  // Enrollment-gated transfer restriction (GoatCoin.sol) — included so
  // viem's simulateContract can decode the revert reason by name.
  { type: "error", name: "TransferRestricted", inputs: [] },
];

export const ENROLLMENT_REGISTRY_ABI = [
  {
    type: "function",
    name: "enrolled",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
  },
  // The founder/safe address (immutable). Read so the UI can identify the
  // founder — e.g. the Market tab shows desk depth only to a desk's own owner
  // and to the founder (debug), never on the public list.
  {
    type: "function",
    name: "safe",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  // Per-wallet EIP-712 nonce for gasless enrollSelfWithSignature (relayer path).
  {
    type: "function",
    name: "nonces",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "DOMAIN_SEPARATOR",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  // Worker self-enroll (pays own gas).
  {
    type: "function",
    name: "enrollSelf",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  // Relayer path: any msg.sender; wallet recovered from EIP-712 Enroll signature.
  {
    type: "function",
    name: "enrollSelfWithSignature",
    stateMutability: "nonpayable",
    inputs: [
      { name: "wallet", type: "address" },
      { name: "deadline", type: "uint256" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [],
  },
  // Ops-only (safe-gated): founder enrollment. Included here (not just
  // WORK_MINTER_ABI) so viem can decode NotSafe reverts by name for the
  // Ops tab's enroll action.
  {
    type: "function",
    name: "setEnrolled",
    stateMutability: "nonpayable",
    inputs: [
      { name: "who", type: "address" },
      { name: "status", type: "bool" },
      { name: "kycRef_", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    type: "event",
    name: "Enrolled",
    inputs: [
      { name: "who", type: "address", indexed: true },
      { name: "status", type: "bool", indexed: false },
      { name: "kycRef", type: "bytes32", indexed: false },
    ],
  },
  { type: "error", name: "NotSafe", inputs: [] },
  { type: "error", name: "Blacklisted", inputs: [] },
  { type: "error", name: "ExpiredSignature", inputs: [] },
  { type: "error", name: "BadSignature", inputs: [] },
];

// WorkerBinding.sol — wallet ↔ GOAT-username registry (FAH attribution).
// Views + meta-tx bind used by desktop bind/enroll + earning status UI.
export const WORKER_BINDING_ABI = [
  {
    type: "function",
    name: "usernameOf",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "function",
    name: "bound",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "nonces",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "walletOfNameHash",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "DOMAIN_SEPARATOR",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "bind",
    stateMutability: "nonpayable",
    inputs: [{ name: "username", type: "string" }],
    outputs: [],
  },
  {
    type: "function",
    name: "bindWithSignature",
    stateMutability: "nonpayable",
    inputs: [
      { name: "wallet", type: "address" },
      { name: "username", type: "string" },
      { name: "deadline", type: "uint256" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [],
  },
  {
    type: "event",
    name: "Bound",
    inputs: [
      { name: "wallet", type: "address", indexed: true },
      { name: "username", type: "string", indexed: false },
    ],
  },
  { type: "error", name: "AlreadyBound", inputs: [] },
  { type: "error", name: "NameTaken", inputs: [] },
  { type: "error", name: "BadUsername", inputs: [] },
  { type: "error", name: "ExpiredSignature", inputs: [] },
  { type: "error", name: "BadSignature", inputs: [] },
];

// EpochSettlement.sol — baseline watermark + claim surface for attribution UI.
// Views only in the desktop pilot UI (claim is daemon/ops path).
export const EPOCH_SETTLEMENT_ABI = [
  {
    type: "function",
    name: "hasBaseline",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "lastClaimedCumulative",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "lastClaimTime",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "uint64" }],
  },
  {
    type: "function",
    name: "capPerDay",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "keeperFee",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
];

export const HOLDBACK_ESCROW_ABI = [
  {
    type: "function",
    name: "holdbackOf",
    stateMutability: "view",
    inputs: [
      { name: "jobId", type: "bytes32" },
      { name: "worker", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "jobReleased",
    stateMutability: "view",
    inputs: [{ name: "jobId", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
];

export const WORK_MINTER_ABI = [
  {
    type: "function",
    name: "jobs",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      { name: "catalogHash", type: "bytes32" },
      { name: "unitReward", type: "uint256" },
      { name: "minted", type: "uint256" },
      { name: "holdbackBps", type: "uint16" },
      { name: "externalAcceptor", type: "address" },
      { name: "founderAcceptOnly", type: "bool" },
      { name: "closed", type: "bool" },
      { name: "lastMint", type: "uint64" },
    ],
  },
  // Ops-only, safe-gated (WorkMinter.sol onlySafe).
  {
    type: "function",
    name: "createJob",
    stateMutability: "nonpayable",
    inputs: [
      { name: "jobId", type: "bytes32" },
      { name: "catalogHash", type: "bytes32" },
      { name: "unitReward", type: "uint256" },
      { name: "holdbackBps", type: "uint16" },
      { name: "externalAcceptor", type: "address" },
      { name: "founderAcceptOnly", type: "bool" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "mintBatch",
    stateMutability: "nonpayable",
    inputs: [
      { name: "jobId", type: "bytes32" },
      { name: "manifestRoot", type: "bytes32" },
      { name: "workers", type: "address[]" },
      { name: "units", type: "uint256[]" },
    ],
    outputs: [],
  },
  // Replay guard (WorkMinter.sol S9 fix a) — read before submitting a mint
  // so the Ops tab can recover from a prior attempt whose on-chain mint
  // succeeded but whose local journal stamp failed (S9 fix b).
  {
    type: "function",
    name: "usedManifest",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "event",
    name: "MintBatch",
    inputs: [
      { name: "jobId", type: "bytes32", indexed: true },
      { name: "manifestRoot", type: "bytes32", indexed: false },
      { name: "totalUnits", type: "uint256", indexed: false },
      { name: "totalGoat", type: "uint256", indexed: false },
    ],
  },
  // Errors kept here (by name) so the Ops tab's simulateContract/writeContract
  // reverts decode readably — see chain/client.js extractErrorName.
  { type: "error", name: "NotSafe", inputs: [] },
  { type: "error", name: "JobExists", inputs: [] },
  { type: "error", name: "JobUnknown", inputs: [] },
  { type: "error", name: "JobClosed", inputs: [] },
  { type: "error", name: "InvalidHoldback", inputs: [] },
  { type: "error", name: "InvalidUnitReward", inputs: [] },
  { type: "error", name: "FounderAcceptRequired", inputs: [] },
  { type: "error", name: "LengthMismatch", inputs: [] },
  { type: "error", name: "HoldbackOpen", inputs: [] },
  { type: "error", name: "ManifestReplayed", inputs: [] },
];

export const BUY_DESK_ABI = [
  {
    type: "function",
    name: "bid",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "depth",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Every BuyDesk instance (factory-created or standalone) exposes its
  // owner — the Market tab reads this per-desk to look up the factory's
  // nameOf(owner) display name and to identify/hide the caller's own desk
  // in the sell-target list (BuyDesk.sol onlyOwner + OwnerCannotSell).
  {
    type: "function",
    name: "owner",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "currentSession",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "id", type: "uint256" },
      { name: "start", type: "uint64" },
      { name: "end", type: "uint64" },
      { name: "cap", type: "uint256" },
    ],
  },
  {
    type: "function",
    name: "sell",
    stateMutability: "nonpayable",
    inputs: [{ name: "goatAmount", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "setBid",
    stateMutability: "nonpayable",
    inputs: [{ name: "newBid", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "openSession",
    stateMutability: "nonpayable",
    inputs: [
      { name: "start", type: "uint64" },
      { name: "end", type: "uint64" },
      { name: "perAccountCapGoat", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "closeSession",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    type: "event",
    name: "Sold",
    inputs: [
      { name: "sessionId", type: "uint256", indexed: true },
      { name: "seller", type: "address", indexed: true },
      { name: "goatAmount", type: "uint256", indexed: false },
      { name: "usdtOut", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "BidSet",
    inputs: [
      { name: "oldBid", type: "uint256", indexed: false },
      { name: "newBid", type: "uint256", indexed: false },
    ],
  },
  { type: "error", name: "NotEnrolled", inputs: [] },
  { type: "error", name: "NoActiveSession", inputs: [] },
  { type: "error", name: "CapExceeded", inputs: [] },
  { type: "error", name: "ZeroPayout", inputs: [] },
  { type: "error", name: "OwnerCannotSell", inputs: [] },
  { type: "error", name: "NotOwner", inputs: [] },
  // OpenZeppelin ERC20 reverts bubbled up through the desk's sell() when it
  // pulls the owner's wallet USDT (allowance model): InsufficientBalance if
  // the owner's wallet balance fell below the payout, InsufficientAllowance
  // if the desk's cap (allowance) is exhausted/unset. Kept here (by name) so
  // viem decodes them instead of surfacing a raw selector to the user.
  {
    type: "error",
    name: "ERC20InsufficientBalance",
    inputs: [
      { name: "sender", type: "address" },
      { name: "balance", type: "uint256" },
      { name: "needed", type: "uint256" },
    ],
  },
  {
    type: "error",
    name: "ERC20InsufficientAllowance",
    inputs: [
      { name: "spender", type: "address" },
      { name: "allowance", type: "uint256" },
      { name: "needed", type: "uint256" },
    ],
  },
];

export const MOCK_USDT_ABI = [
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  // Plain ERC20 transfer — the Wallet tab's "Send USDT" uses this so a user
  // can move their own USDT to any address (MockUSDT is ungated, unlike
  // enrollment-gated GoatCoin). In the allowance desk model USDT is always
  // held in the user's own wallet, so this is how they move it out.
  {
    type: "function",
    name: "transfer",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "allowance",
    stateMutability: "view",
    inputs: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  // Open on testnet — anyone may mint themselves MockUSDT (Ops "faucet"
  // button). Never deployed to mainnet (MockUSDT.sol doc comment).
  {
    type: "function",
    name: "mint",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
];

// BuyDeskFactory.sol (docs/superpowers/specs/2026-07-13-donor-buydesk-factory-
// multidesk-design.md §2.1) — deploys per-owner BuyDesk instances. Any
// enrolled wallet (every worker already is one) becomes a donor by calling
// createDesk: same wallet, no second key, no extra founder approval. Market
// tab (desktop/src/tabs/Market.jsx) is the only consumer.
export const BUY_DESK_FACTORY_ABI = [
  {
    type: "function",
    name: "createDesk",
    stateMutability: "nonpayable",
    inputs: [{ name: "name", type: "string" }],
    outputs: [{ name: "desk", type: "address" }],
  },
  {
    type: "function",
    name: "setDeskName",
    stateMutability: "nonpayable",
    inputs: [{ name: "name", type: "string" }],
    outputs: [],
  },
  {
    type: "function",
    name: "deskOf",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "desks",
    stateMutability: "view",
    inputs: [{ name: "", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "desksLength",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "nameOf",
    stateMutability: "view",
    inputs: [{ name: "", type: "address" }],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "event",
    name: "DeskCreated",
    inputs: [
      { name: "owner", type: "address", indexed: true },
      { name: "desk", type: "address", indexed: true },
      { name: "index", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "DeskNamed",
    inputs: [
      { name: "owner", type: "address", indexed: true },
      { name: "desk", type: "address", indexed: true },
      { name: "name", type: "string", indexed: false },
    ],
  },
  { type: "error", name: "AlreadyHasDesk", inputs: [] },
  { type: "error", name: "NoDesk", inputs: [] },
  { type: "error", name: "ZeroAddress", inputs: [] },
];
