// "Add another wallet" overlay for the Wallet tab. Create requires a GOAT-username that is
// bound to this wallet's FAH profile (and stored per-wallet so unlock swaps FAH identity).
// Import adopts an on-chain bound username when present. Unlock always syncs the active
// wallet's stored FAH profile (see walletProfiles.js) — Alice→Rookie, Bob→Bob's name.
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { invoke } from "@tauri-apps/api/core";
import { createWallet, importWallet, unlock } from "../chain/wallet.js";
import { commandError } from "../chain/errors.js";
import { KEY_IMPORT_WARNING } from "../chain/client.js";
import { readBoundUsername } from "../chain/attribution.js";
import { tryAutoEnroll } from "../chain/enroll.js";
import { useNetwork } from "./NetworkSwitch.jsx";
import {
  cleanCustomName, fullUsername, generatePasskey, isValidPasskeyInput,
  GOAT_USERNAME_PREFIX,
} from "../identity.js";
import { bindWalletFahProfile } from "../walletProfiles.js";
import { canSubmitImport, showPasswordMismatch, MIN_PW } from "../walletFormRules.js";
import { reducedVariants, stepVariants } from "../onboarding/stepMotion.js";
import {
  KEY_REVEAL_CONFIRM, KEY_REVEAL_FALLBACK, KEY_REVEAL_TITLE, KEY_REVEAL_WARNING,
  PASSKEY_HELP, PASSKEY_LABEL, USERNAME_CAUTION,
} from "../onboarding/copy.js";

/** view: "choose" | "create" | "import" | "reveal"
 *
 * T28: presentation is REUSED from the wizard, not hand-styled — the card carries
 * the wizard's step-card classes (`wizard__step glass glass--static`) and the
 * views switch with the wizard's own choreography (stepMotion.js presets under
 * AnimatePresence popLayout). The backdrop keeps .firstrun-overlay positioning.
 * No exit animation on close: the parent unmounts the overlay directly (adding
 * one would require an AnimatePresence in Wallet.jsx — out of scope).
 *
 * T29 F1: rendered through a PORTAL to document.body. The overlay mounts inside
 * .wallet-manager, a .wallet-section with backdrop-filter (glass). A backdrop-
 * filter ancestor becomes the containing block for position:fixed AND its own
 * stacking context, so the overlay was trapped inside the wallet card and
 * sibling panels (Balance) painted over it — a z-index bump alone can't escape.
 * Portaling to body lifts it out of every backdrop-filter/transform ancestor. */
export default function AddWalletOverlay({ onClose }) {
  const [view, setView] = useState("choose");
  const [newWallet, setNewWallet] = useState(null); // { name, address } once created
  const reduced = useReducedMotion();
  const variants = reduced ? reducedVariants : stepVariants;

  return createPortal(
    <motion.div
      className="firstrun-overlay"
      role="dialog"
      aria-modal="true"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
    >
      <motion.div
        className="wizard__step glass glass--static add-wallet-card"
        initial={reduced ? { opacity: 0 } : { opacity: 0, scale: 0.96 }}
        animate={reduced ? { opacity: 1 } : { opacity: 1, scale: 1 }}
        transition={{ duration: 0.3, ease: [0.25, 0.1, 0.25, 1] }}
      >
        <AnimatePresence mode="popLayout">
          <motion.div key={view} variants={variants} initial="enter" animate="center" exit="exit">
            {view === "choose" && <ChooseView goTo={setView} onClose={onClose} />}
            {view === "create" && (
              <CreateView
                onClose={onClose}
                onCreated={(meta) => {
                  setNewWallet(meta);
                  setView("reveal");
                }}
              />
            )}
            {view === "import" && <ImportView onClose={onClose} />}
            {view === "reveal" && <RevealView wallet={newWallet} onDone={onClose} />}
          </motion.div>
        </AnimatePresence>
      </motion.div>
    </motion.div>,
    document.body,
  );
}

function ChooseView({ goTo, onClose }) {
  return (
    <div className="wizard-step">
      <h2>Add another wallet</h2>
      <div className="wizard-actions">
        <button type="button" className="primary-cta" onClick={() => goTo("create")}>
          Create a wallet
        </button>
        <button type="button" className="btn-outline" onClick={() => goTo("import")}>
          Import a wallet
        </button>
        <button type="button" className="btn-outline" onClick={onClose}>
          Cancel
        </button>
      </div>
    </div>
  );
}

function CreateView({ onClose, onCreated }) {
  const { networkId } = useNetwork();
  const [name, setName] = useState("");
  const [user, setUser] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [passkey, setPasskey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const canSubmit =
    name.trim() &&
    cleanCustomName(user) &&
    pw.length >= MIN_PW &&
    pw === pw2 &&
    isValidPasskeyInput(passkey) &&
    !busy;

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    try {
      const username = fullUsername(user);
      const pk = passkey.trim() || generatePasskey();
      const meta = await createWallet(name.trim(), pw);
      await unlock(name.trim(), pw);
      // Non-blocking: FAH bind + enroll failures surface in Attribution with retry.
      try {
        await bindWalletFahProfile(meta.address, { username, passkey: pk });
        await tryAutoEnroll(networkId, meta.address);
      } catch { /* Attribution */ }
      onCreated(meta);
    } catch (err) {
      setError(commandError(err));
      setBusy(false);
    }
  }

  return (
    <form className="wizard-step" onSubmit={submit}>
      <h2>Create a wallet</h2>
      <input
        type="text"
        placeholder="Wallet name (local label)"
        value={name}
        onChange={(e) => setName(e.target.value)}
        autoComplete="off"
      />
      <label className="muted">GOAT username (FAH identity for this wallet)</label>
      <div className="firstrun-input-row">
        <span className="firstrun-prefix">{GOAT_USERNAME_PREFIX}</span>
        <input
          type="text"
          placeholder="your name (letters, digits, _)"
          value={user}
          onChange={(e) => setUser(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </div>
      <p className="warning-text">{USERNAME_CAUTION}</p>
      <input
        type="password"
        placeholder={`Password (min ${MIN_PW} chars)`}
        value={pw}
        onChange={(e) => setPw(e.target.value)}
      />
      <input
        type="password"
        placeholder="Confirm password"
        value={pw2}
        onChange={(e) => setPw2(e.target.value)}
      />
      <label className="muted">{PASSKEY_LABEL}</label>
      <input
        type="password"
        placeholder="32-hex passkey (leave empty to auto-generate)"
        value={passkey}
        onChange={(e) => setPasskey(e.target.value)}
      />
      <p className="muted">{PASSKEY_HELP}</p>
      {/* T27 P9: validation errors are visible, not just a disabled button. */}
      {pw.length > 0 && pw.length < MIN_PW && (
        <p className="error-text">Password must be at least {MIN_PW} characters.</p>
      )}
      {pw2.length > 0 && pw !== pw2 && <p className="error-text">Passwords do not match.</p>}
      {!isValidPasskeyInput(passkey) && (
        <p className="error-text">Passkey must be empty or exactly 32 hex characters.</p>
      )}
      {error && <p className="error-text">{error}</p>}
      <div className="wizard-actions">
        <button type="submit" className="primary-cta" disabled={!canSubmit}>
          {busy ? "Creating…" : "Create wallet"}
        </button>
        <button type="button" className="btn-outline" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function ImportView({ onClose }) {
  const { networkId } = useNetwork();
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [key, setKey] = useState("");
  const [passkey, setPasskey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const canSubmit = canSubmitImport({ name, pw, pw2, key, passkey, busy });

  async function submit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    try {
      const trimmedKey = key.trim();
      const meta = await importWallet(name.trim(), pw, trimmedKey);
      setKey(""); // drop the pasted key from state immediately on success
      await unlock(name.trim(), pw);
      // If this address already has an on-chain GOAT-username bind, adopt it into the
      // per-wallet FAH profile so later unlocks restore the right identity.
      try {
        const bound = await readBoundUsername(networkId, meta.address);
        if (bound) {
          await bindWalletFahProfile(meta.address, {
            username: bound,
            passkey: passkey.trim() || generatePasskey(),
          });
          await tryAutoEnroll(networkId, meta.address);
        }
      } catch { /* Attribution */ }
      onClose();
    } catch (err) {
      setError(commandError(err));
      setBusy(false);
    }
  }

  return (
    <form className="wizard-step" onSubmit={submit}>
      <h2>Import a wallet</h2>
      <p className="warning-text">{KEY_IMPORT_WARNING}</p>
      <input
        type="text"
        placeholder="Wallet name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        autoComplete="off"
      />
      <input
        type="password"
        placeholder={`Password (min ${MIN_PW} chars)`}
        value={pw}
        onChange={(e) => setPw(e.target.value)}
      />
      <input
        type="password"
        placeholder="Confirm password"
        value={pw2}
        onChange={(e) => setPw2(e.target.value)}
      />
      <input
        type="password"
        placeholder="0x… private key"
        value={key}
        onChange={(e) => setKey(e.target.value)}
      />
      <label className="muted">{PASSKEY_LABEL}</label>
      <input
        type="password"
        placeholder="32-hex passkey (leave empty to auto-generate)"
        value={passkey}
        onChange={(e) => setPasskey(e.target.value)}
      />
      <p className="muted">{PASSKEY_HELP}</p>
      {/* T27 P9: validation errors are visible, not just a disabled button. */}
      {pw.length > 0 && pw.length < MIN_PW && (
        <p className="error-text">Password must be at least {MIN_PW} characters.</p>
      )}
      {showPasswordMismatch(pw, pw2) && <p className="error-text">Passwords do not match.</p>}
      {!isValidPasskeyInput(passkey) && (
        <p className="error-text">Passkey must be empty or exactly 32 hex characters.</p>
      )}
      {error && <p className="error-text">{error}</p>}
      <div className="wizard-actions">
        <button type="submit" className="primary-cta" disabled={!canSubmit}>
          {busy ? "Importing…" : "Import"}
        </button>
        <button type="button" className="btn-outline" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}

// Exact key-reveal UX reused from onboarding/steps/KeyReveal.jsx (A1: create path still shows
// the one-time reveal; import path skips it — the user already has the key).
function RevealView({ wallet, onDone }) {
  const [key, setKey] = useState(null); // string | null; null = reveal failed
  const [failed, setFailed] = useState(false);
  const [written, setWritten] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    invoke("wallet_reveal_key", { expectedAddress: wallet?.address ?? "" })
      .then((k) => {
        if (!cancelled) setKey(k);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
      setKey(null); // key never outlives this view
    };
  }, [wallet?.address]);

  return (
    <div className="wizard-step">
      <h2>{KEY_REVEAL_TITLE}</h2>
      <p className="warning-text">{KEY_REVEAL_WARNING}</p>
      {key ? (
        <div className="key-chip">
          <code>{key}</code>
          <button
            type="button"
            className="btn-outline"
            onClick={async () => {
              await navigator.clipboard.writeText(key);
              setCopied(true);
            }}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      ) : failed ? (
        <p className="muted">{KEY_REVEAL_FALLBACK}</p>
      ) : (
        <p className="muted">Revealing…</p>
      )}
      <label className="wizard-confirm">
        <input type="checkbox" checked={written} onChange={(e) => setWritten(e.target.checked)} />
        {KEY_REVEAL_CONFIRM}
      </label>
      <div className="wizard-actions">
        <button
          type="button"
          className="primary-cta"
          disabled={failed ? false : key ? !written : true}
          onClick={onDone}
        >
          Done
        </button>
      </div>
    </div>
  );
}
