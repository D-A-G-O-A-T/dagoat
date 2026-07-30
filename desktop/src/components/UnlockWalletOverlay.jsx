// Modal: unlock a stored wallet (default = last used). Used when Earn GOAT is on
// and the user hits Start contributing without an unlocked wallet.
import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { motion, useReducedMotion } from "motion/react";
import {
  listWallets,
  loadLastWalletName,
  unlock,
  useUnlockProgress,
} from "../chain/wallet.js";
import { commandError } from "../chain/errors.js";

/** Pure: prefer last-used name if still present, else first listed wallet. */
export function pickWalletForUnlock(wallets, lastName) {
  const list = Array.isArray(wallets) ? wallets : [];
  if (list.length === 0) return null;
  if (lastName) {
    const hit = list.find((w) => w?.name === lastName);
    if (hit) return hit;
  }
  return list[0];
}

/**
 * @param {{ onClose: () => void, onUnlocked: (meta: { name: string, address: string }) => void }} props
 */
export default function UnlockWalletOverlay({ onClose, onUnlocked }) {
  const reduced = useReducedMotion();
  const unlockProgress = useUnlockProgress();
  const [wallets, setWallets] = useState([]);
  const [selectedName, setSelectedName] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [loadingList, setLoadingList] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [list, last] = await Promise.all([
          listWallets().catch(() => []),
          loadLastWalletName(),
        ]);
        if (cancelled) return;
        const arr = Array.isArray(list) ? list : [];
        setWallets(arr);
        const pick = pickWalletForUnlock(arr, last);
        setSelectedName(pick?.name ?? "");
      } finally {
        if (!cancelled) setLoadingList(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const pending = unlockProgress.status === "pending";
  const message = formError || (unlockProgress.status === "error" ? unlockProgress.message : "");

  async function handleSubmit(e) {
    e.preventDefault();
    if (!selectedName) {
      setFormError("Pick a wallet.");
      return;
    }
    if (!password) {
      setFormError("Enter the wallet password.");
      return;
    }
    if (pending) return;
    setFormError("");
    try {
      const meta = await unlock(selectedName, password);
      setPassword("");
      onUnlocked?.(meta);
    } catch (err) {
      // unlockProgress already has the message; keep password for retry
      if (!unlockProgress.message) setFormError(commandError(err));
    }
  }

  return createPortal(
    <motion.div
      className="firstrun-overlay"
      role="dialog"
      aria-modal="true"
      aria-labelledby="unlock-wallet-title"
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
        <form className="wizard-step" onSubmit={handleSubmit}>
          <h2 id="unlock-wallet-title">Unlock wallet</h2>
          <p className="muted">
            Earn GOAT is on — unlock a wallet so Folding@home work can be attributed before
            contributing.
          </p>
          {loadingList ? (
            <p className="muted">Loading wallets…</p>
          ) : wallets.length === 0 ? (
            <p className="error-text">No stored wallet. Create one in the Wallet tab first.</p>
          ) : (
            <>
              <div className="unlock-wallet-row">
                <label className="muted unlock-wallet-label" htmlFor="unlock-wallet-select">
                  Wallet :
                </label>
                <select
                  id="unlock-wallet-select"
                  value={selectedName}
                  onChange={(e) => setSelectedName(e.target.value)}
                  disabled={pending}
                >
                  {wallets.map((w) => (
                    <option key={w.name} value={w.name}>
                      {w.name}
                      {w.address
                        ? ` · ${String(w.address).slice(0, 6)}…${String(w.address).slice(-4)}`
                        : ""}
                    </option>
                  ))}
                </select>
              </div>
              <input
                type="password"
                placeholder="Wallet password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus
                disabled={pending}
              />
            </>
          )}
          {message && <p className="error-text">{message}</p>}
          <div className="wizard-actions">
            <button
              type="submit"
              className="primary-cta"
              disabled={pending || loadingList || wallets.length === 0}
            >
              {pending ? "Unlocking…" : "Unlock"}
            </button>
            <button type="button" className="btn-outline" onClick={onClose} disabled={pending}>
              Cancel
            </button>
          </div>
        </form>
      </motion.div>
    </motion.div>,
    document.body,
  );
}
