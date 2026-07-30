// Every user-facing wizard/shell string lives here so copy.test.js can enforce
// the honesty rules (spec §13) over ALL of it. Do not inline copy in components.

export const DISCLAIMER_TITLE = "Before you start";
export const DISCLAIMER_PARAGRAPHS = [
  { heading: "", body: "D.A. G.O.A.T. is a research pilot." },
  { heading: "What this app does", body: "It downloads and runs the official Folding@home client on your computer. Your completed work units support real disease research. If earning is enabled, the pilot attributes your verified work on a public test network." },
  { heading: "About GOAT tokens", body: "GOAT currently exists on a test network only. It has no monetary value today and no guarantee of future value. GOAT is not an investment, and nothing here is a promise of payment." },
  { heading: "About your wallet", body: "Your key is created and stored only on this device, encrypted with your password. If you lose both your written-down key and your password, access cannot be recovered by anyone." },
  { heading: "Third party", body: "Folding@home is an independent research project with its own terms." },
  { heading: "", body: "By choosing Accept, you confirm you understand the above." },
];
export const DISCLAIMER_ACCEPT = "Accept and continue";
export const DISCLAIMER_DECLINE = "Decline";

export const WALLET_GATE_TITLE = "Set up your GOAT wallet";
export const CREATE_CARD = { title: "Create a wallet", body: "Generate a fresh key on this device, sealed under your password." };
export const IMPORT_CARD = { title: "Import a wallet", body: "Bring an existing 0x private key. It is sealed under a new password." };
export const OPT_OUT_LINK = "Contribute without a wallet — your GPU still supports public science; you just won't receive GOAT. You can change this anytime.";

export const USERNAME_CAUTION = "⚠ Bound to your wallet permanently — it cannot be changed later.";
export const PASSKEY_LABEL = "Folding@home passkey (optional)";
export const PASSKEY_HELP = "If you already have one from Folding@home, paste it here to keep your bonus. Otherwise leave this empty and we'll create an identity token for you.";

export const KEY_REVEAL_TITLE = "Write down your key";
export const KEY_REVEAL_WARNING = "This is the only time it is shown automatically. Anyone with this key controls your GOAT. Write it down and store it offline.";
export const KEY_REVEAL_CONFIRM = "I wrote it down";
export const KEY_REVEAL_FALLBACK = "Your key is sealed in the encrypted vault — you can reveal it later from the Wallet tab.";

export const EARN_SWITCH_LABEL = "Earn GOAT";
export const EARN_SWITCH_CAPTION = "Contributions always support science; off = no GOAT attribution.";
export const EARNING_OFF_CARD = "Earning is off. Flip the switch to receive GOAT for your contributions (testnet pilot).";

// A2 (spec §16): the FAH passkey is shown read-only in Attribution — never editable in-app.
export const PASSKEY_ATTRIBUTION_NOTE =
  "Not editable in-app — changing it would interrupt your Folding@home bonus continuity. Manage it in Folding@home's own tools.";

export const ALL_COPY = [
  DISCLAIMER_TITLE,
  ...DISCLAIMER_PARAGRAPHS.flatMap((p) => [p.heading, p.body]),
  DISCLAIMER_ACCEPT, DISCLAIMER_DECLINE, WALLET_GATE_TITLE,
  CREATE_CARD.title, CREATE_CARD.body, IMPORT_CARD.title, IMPORT_CARD.body,
  OPT_OUT_LINK, USERNAME_CAUTION, PASSKEY_LABEL, PASSKEY_HELP,
  KEY_REVEAL_TITLE, KEY_REVEAL_WARNING, KEY_REVEAL_CONFIRM, KEY_REVEAL_FALLBACK,
  EARN_SWITCH_LABEL, EARN_SWITCH_CAPTION, EARNING_OFF_CARD,
  PASSKEY_ATTRIBUTION_NOTE,
];
